"""
demo.py
=======
End-to-end demonstration of the IoT Smart Home Security framework.

Run:  python3 demo.py

Sections:
  1. Provisioning        - devices get Hub-signed identity certificates
  2. Secure handshake     - ECDH + challenge-response per device
  3. Legitimate operation - authorized encrypted commands succeed
  4. Attack simulations   - rogue device, tampering, replay, wrong scope,
                            expired token, missing session (MITM w/o keys)
"""

import sys
import time
import json

from hub import Hub, SecurityError
from devices import SmartLock, SecurityCamera, MotionSensor
import crypto_utils as cu

# Run "python3 demo.py --auto" to skip the pauses and print everything
# straight through (useful for testing). Default (no flag) is the
# presentation mode: it stops before each beat so you can talk, then
# waits for you to press Enter before the terminal prints that part.
INTERACTIVE = "--auto" not in sys.argv


def pause(msg="press Enter to run this step..."):
    if INTERACTIVE:
        input(f"\n>> {msg}")


def section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main():
    results = {"pass": 0, "fail": 0}

    def expect(label, condition):
        results["pass" if condition else "fail"] += 1
        print(f"  {'PASS' if condition else 'FAIL'} -> {label}")

    # ---------------------------------------------------------------
    pause("about to provision 3 devices with Hub-signed certificates")
    section("1. PROVISIONING  (Hub acts as Certificate Authority)")
    hub = Hub()
    lock = SmartLock("lock-front-door")
    camera = SecurityCamera("camera-driveway")
    sensor = MotionSensor("sensor-hallway")

    for dev in (lock, camera, sensor):
        dev.register_with_hub(hub)

    # ---------------------------------------------------------------
    pause("about to run the ECDH handshake for each device")
    section("2. SECURE HANDSHAKE  (ECDH key exchange + challenge-response auth)")
    for dev in (lock, camera, sensor):
        dev.connect(hub)
    expect("all three devices hold an established AES-256 session key",
           all(d.session_key is not None for d in (lock, camera, sensor)))
    expect("each device's session key is distinct",
           len({lock.session_key, camera.session_key, sensor.session_key}) == 3)

    # ---------------------------------------------------------------
    pause("about to send 3 real, authorized commands (unlock, view stream, read sensor)")
    section("3. LEGITIMATE OPERATION  (Control Access: scoped, short-lived tokens)")

    # Owner's phone app asks the Hub for permission to unlock the door.
    unlock_token = hub.issue_token(lock.device_id, scopes=["unlock", "lock"], ttl_seconds=60)
    pkt = lock.build_command_packet("unlock", unlock_token)
    resp_pkt = hub.handle_and_execute(lock, pkt)
    resp = lock.decrypt_response(resp_pkt)
    print(f"  lock responded: {resp}")
    expect("smart lock unlocked via authenticated+encrypted+authorized command",
           resp["status"] == "unlocked" and lock.locked is False)

    view_token = hub.issue_token(camera.device_id, scopes=["view_stream"], ttl_seconds=60)
    pkt = camera.build_command_packet("view_stream", view_token)
    resp = camera.decrypt_response(hub.handle_and_execute(camera, pkt))
    print(f"  camera responded: {resp}")
    expect("camera streamed video for an authorized viewer", resp["status"] == "streaming")

    sensor_token = hub.issue_token(sensor.device_id, scopes=["read_sensor"], ttl_seconds=60)
    pkt = sensor.build_command_packet("read_sensor", sensor_token)
    resp = sensor.decrypt_response(hub.handle_and_execute(sensor, pkt))
    print(f"  sensor responded: {resp}")
    expect("motion sensor reading retrieved", resp["status"] == "ok")

    # ---------------------------------------------------------------
    pause("about to start the 6 attack simulations")
    section("4. ATTACK SIMULATIONS")

    # --- 4a. Rogue / unregistered device tries to join the network ---
    pause("attack 1/6: a rogue device with no valid Hub certificate")
    print("\n-- 4a. Rogue device with a self-signed (uncertified) identity --")
    rogue = SmartLock("lock-front-door")          # impersonating the real lock
    rogue.cert = {  # forges its own "certificate" instead of registering with the Hub
        "body": {
            "device_id": "lock-front-door",
            "public_key": cu.b64(cu.raw_public_bytes(rogue.identity_pub)),
            "role": "smart_lock",
            "issued_at": time.time(),
            "expires_at": time.time() + 3600,
        },
        "signature": cu.b64(b"\x00" * 64),  # not signed by the real Hub CA
    }
    try:
        rogue.connect(hub)
        expect("rogue device WITHOUT a Hub-signed certificate is rejected", False)
    except SecurityError as e:
        print(f"  Hub rejected rogue device: {e}")
        expect("rogue device WITHOUT a Hub-signed certificate is rejected", True)

    # --- 4b. Tampering in transit ---
    pause("attack 2/6: flipping one byte in an intercepted, otherwise-valid ciphertext")
    print("\n-- 4b. Attacker flips a byte in an intercepted ciphertext --")
    token = hub.issue_token(lock.device_id, scopes=["lock"], ttl_seconds=60)
    pkt = lock.build_command_packet("lock", token)
    tampered = dict(pkt)
    raw = bytearray(cu.base64.b64decode(tampered["ciphertext"]))
    raw[0] ^= 0xFF
    tampered["ciphertext"] = cu.b64(bytes(raw))
    try:
        hub.handle_and_execute(lock, tampered)
        expect("tampered ciphertext is rejected (AES-GCM tag check)", False)
    except SecurityError as e:
        print(f"  Hub rejected tampered packet: {e}")
        expect("tampered ciphertext is rejected (AES-GCM tag check)", True)

    # --- 4c. Replay attack ---
    pause("attack 3/6: capturing a valid command and resending it unchanged")
    print("\n-- 4c. Attacker captures a valid command and re-sends it later --")
    token = hub.issue_token(lock.device_id, scopes=["unlock"], ttl_seconds=60)
    original_pkt = lock.build_command_packet("unlock", token)
    hub.handle_and_execute(lock, original_pkt)     # goes through the first time
    print("  (original command accepted)")
    try:
        hub.handle_and_execute(lock, original_pkt)  # attacker resends identical packet
        expect("replayed (identical) packet is rejected", False)
    except SecurityError as e:
        print(f"  Hub rejected replayed packet: {e}")
        expect("replayed (identical) packet is rejected", True)

    # --- 4d. Token used outside its granted scope (privilege escalation attempt) ---
    pause("attack 4/6: using a 'lock only' token to try to unlock the door")
    print("\n-- 4d. Camera-viewing token used to try to unlock the door --")
    narrow_token = hub.issue_token(lock.device_id, scopes=["lock"], ttl_seconds=60)  # 'lock' only
    pkt = lock.build_command_packet("unlock", narrow_token)   # tries 'unlock' anyway
    try:
        hub.handle_and_execute(lock, pkt)
        expect("out-of-scope action is rejected", False)
    except SecurityError as e:
        print(f"  Hub rejected out-of-scope command: {e}")
        expect("out-of-scope action is rejected", True)

    # --- 4e. Expired token ---
    pause("attack 5/6: using a token after its TTL has run out")
    print("\n-- 4e. Token used after its TTL has elapsed --")
    short_token = hub.issue_token(lock.device_id, scopes=["lock"], ttl_seconds=1)
    time.sleep(1.2)
    pkt = lock.build_command_packet("lock", short_token)
    try:
        hub.handle_and_execute(lock, pkt)
        expect("expired token is rejected", False)
    except SecurityError as e:
        print(f"  Hub rejected expired token: {e}")
        expect("expired token is rejected", True)

    # --- 4f. Command sent with no established session (skips handshake) ---
    pause("attack 6/6: sending a command to a device that never handshook with the Hub")
    print("\n-- 4f. Attacker sends a command to a device with no active session --")
    ghost = SmartLock("lock-back-door")
    ghost.register_with_hub(hub)
    ghost.session_key = b"\x01" * 32     # attacker guesses/fabricates a key, never handshook
    forged_token = hub.issue_token(ghost.device_id, scopes=["unlock"], ttl_seconds=60)
    pkt = ghost.build_command_packet("unlock", forged_token)
    try:
        hub.handle_and_execute(ghost, pkt)
        expect("command without a Hub-established session is rejected", False)
    except SecurityError as e:
        print(f"  Hub rejected command: {e}")
        expect("command without a Hub-established session is rejected", True)

    # ---------------------------------------------------------------
    pause("about to print the final summary")
    section("SUMMARY")
    total = results["pass"] + results["fail"]
    print(f"  {results['pass']} / {total} checks passed")
    print(f"  Hub log entries: {len(hub.log)}")
    return results


if __name__ == "__main__":
    main()

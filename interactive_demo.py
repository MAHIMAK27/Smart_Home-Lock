"""
interactive_demo.py
====================
Live seminar demo: type real commands and watch them travel through
the secure pipeline, step by step. Also lets you trigger attacker
simulations on demand (tamper, replay, rogue device) against the same
running system.

Problem statement:
  Secure communication between smart home devices to prevent
  unauthorized access and device manipulation.

Mapping:
  Unauthorized access  -> Ed25519 device certificates + challenge-
                           response authentication (Hub acts as CA)
  Device manipulation  -> AES-256-GCM integrity check + per-session
                           replay protection + scoped access tokens

Run:  python3 interactive_demo.py
"""

import json
import time

from hub import Hub, SecurityError
from devices import SmartLock, SmartLight
import crypto_utils as cu


LINE = "-" * 60


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def step(n, text):
    print(f"\n[{n}] {text}")


def show_json(label, obj):
    print(f"    {label}: {json.dumps(obj)}")


class DemoState:
    """Tracks the most recently sent packet so attack options can act on it."""
    def __init__(self):
        self.last_device = None
        self.last_packet = None
        self.last_token = None


def send_command(hub, device, action, scopes, state, params=None):
    """The full pipeline, printed step by step, mirroring:
       User -> Encrypt -> Network (attacker view) -> Hub verifies -> Execute -> Response
    """
    banner(f"SENDING COMMAND: '{action}' -> {device.device_id}")

    step(1, f"User/app requests action '{action}' on {device.device_id}")

    token = hub.issue_token(device.device_id, scopes=scopes, ttl_seconds=60)
    step(2, "Hub issues a scoped, 60s access token")
    show_json("token scopes", token["payload"]["scopes"])

    packet = device.build_command_packet(action, token, params)
    step(3, "Device encrypts the command with AES-256-GCM (session key from ECDH handshake)")
    print(f"    plaintext command : {{'action': '{action}', 'seq': {device.seq}, ...}}")
    print(f"    ciphertext on wire: {packet['ciphertext'][:48]}...")

    step(4, "Network / attacker's view")
    print("    An eavesdropper on the network sees only:")
    print(f"      {packet['ciphertext'][:48]}...")
    print("    Can they read the command? NO — it's AES-256-GCM ciphertext.")

    step(5, "Hub receives the packet: decrypts, checks sequence number, verifies token")
    try:
        resp_packet = hub.handle_and_execute(device, packet)
    except SecurityError as e:
        print(f"    REJECTED: {e}")
        state.last_device, state.last_packet, state.last_token = device, packet, token
        return

    resp = device.decrypt_response(resp_packet)
    step(6, f"Command authorized. Device executed it -> {resp}")

    state.last_device = device
    state.last_packet = packet
    state.last_token = token
    print(f"\n>>> RESULT: {resp}")


def attack_replay(hub, state):
    if state.last_packet is None or state.last_device is None:
        print("\nSend a real command first (option 1 or 2), then try this attack on it.")
        return
    banner("ATTACK SIMULATION: replay")
    step(1, "Attacker captured the last valid, already-used packet")
    step(2, "Attacker re-sends the exact same packet again")
    try:
        hub.handle_and_execute(state.last_device, state.last_packet)
        print("    UNEXPECTED: replay was accepted (should not happen)")
    except SecurityError as e:
        print(f"    REJECTED by Hub: {e}")


def attack_rogue(hub):
    banner("ATTACK SIMULATION: rogue / uncertified device")
    step(1, "An attacker device claims to be 'lock-front-door' with a self-signed certificate")
    rogue = SmartLock("lock-front-door")
    rogue.cert = {
        "body": {
            "device_id": "lock-front-door",
            "public_key": cu.b64(cu.raw_public_bytes(rogue.identity_pub)),
            "role": "smart_lock",
            "issued_at": time.time(),
            "expires_at": time.time() + 3600,
        },
        "signature": cu.b64(b"\x00" * 64),  # never actually signed by the Hub's CA key
    }
    step(2, "Rogue device attempts the handshake")
    try:
        rogue.connect(hub)
        print("    UNEXPECTED: rogue device was accepted (should not happen)")
    except SecurityError as e:
        print(f"    REJECTED by Hub: {e}")


def attack_tamper(hub, state):
    if state.last_packet is None or state.last_device is None:
        print("\nSend a real command first (option 1 or 2), then try this attack on it.")
        return
    banner("ATTACK SIMULATION: bit-flip tampering")
    step(1, "Attacker intercepts the last ciphertext sent")
    tampered = dict(state.last_packet)
    raw = bytearray(cu.base64.b64decode(tampered["ciphertext"]))
    raw[0] ^= 0xFF
    tampered["ciphertext"] = cu.b64(bytes(raw))
    step(2, "Attacker flips one byte and re-sends it to the Hub")
    try:
        hub.handle_and_execute(state.last_device, tampered)
        print("    UNEXPECTED: tampered packet was accepted (should not happen)")
    except SecurityError as e:
        print(f"    REJECTED by Hub: {e}")


def setup():
    print("Setting up: provisioning devices and running the secure handshake...")
    hub = Hub(verbose=False)
    lock = SmartLock("lock-front-door")
    light = SmartLight("light-living-room")

    for dev in (lock, light):
        dev.register_with_hub(hub)
        dev.connect(hub)

    print(f"  Smart Lock  ({lock.device_id})  - certificate issued, secure session established")
    print(f"  Smart Light ({light.device_id}) - certificate issued, secure session established")
    return hub, lock, light


def menu():
    print("\n" + LINE)
    print("SMART HOME SECURITY DEMO")
    print(LINE)
    print("  1) Send command to Smart Lock   (unlock / lock)")
    print("  2) Send command to Smart Light  (on / off)")
    print("  3) Attack: tamper with the last message")
    print("  4) Attack: replay the last message")
    print("  5) Attack: rogue device with a fake certificate")
    print("  6) Exit")
    return input("Choose an option: ").strip()


def main():
    print(LINE)
    print("SECURE COMMUNICATION BETWEEN SMART HOME DEVICES")
    print("Preventing unauthorized access and device manipulation")
    print(LINE)
    hub, lock, light = setup()
    state = DemoState()

    while True:
        choice = menu()
        if choice == "1":
            cmd = input("  Enter command (unlock/lock): ").strip().lower()
            if cmd not in ("unlock", "lock"):
                print("  Unknown command.")
                continue
            send_command(hub, lock, cmd, scopes=["unlock", "lock"], state=state)
        elif choice == "2":
            cmd = input("  Enter command (on/off): ").strip().lower()
            action = {"on": "turn_on", "off": "turn_off"}.get(cmd)
            if action is None:
                print("  Unknown command.")
                continue
            send_command(hub, light, action, scopes=["turn_on", "turn_off"], state=state)
        elif choice == "3":
            attack_tamper(hub, state)
        elif choice == "4":
            attack_replay(hub, state)
        elif choice == "5":
            attack_rogue(hub)
        elif choice == "6":
            print("Exiting demo.")
            break
        else:
            print("  Unknown option.")


if __name__ == "__main__":
    main()

"""
devices.py
==========
IoT device-side implementation. Each device:
  1. Generates its own Ed25519 identity keypair (done once, at
     provisioning) and gets it certified by the Hub.
  2. Performs the ECDH handshake + challenge-response authentication
     with the Hub to establish an authenticated, encrypted session.
  3. Requests a scoped access token from the Hub and uses it to send
     encrypted, replay-protected commands.
"""

import json
import crypto_utils as cu


class IoTDevice:
    role = "generic"

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.identity_priv, self.identity_pub = cu.generate_identity_keypair()
        self.cert = None            # filled in at registration
        self.session_key = None
        self.seq = 0

    # ---- provisioning ---------------------------------------------------
    def register_with_hub(self, hub):
        self.cert = hub.register_device(self.device_id, self.identity_pub, self.role)

    # ---- handshake --------------------------------------------------------
    def connect(self, hub):
        ecdh_priv, ecdh_pub = cu.generate_ecdh_keypair()
        self._ecdh_priv = ecdh_priv

        challenge, hub_ecdh_pub_bytes = hub.handshake_step1_receive_hello(
            self.device_id, self.cert, cu.raw_public_bytes(ecdh_pub)
        )

        signature = cu.sign_challenge(self.identity_priv, challenge)
        hub.handshake_step2_verify_response(self.device_id, signature)

        self.session_key = cu.derive_session_key(
            self._ecdh_priv, hub_ecdh_pub_bytes, context=f"{hub.name}|{self.device_id}".encode()
        )

    # ---- building an authorized, encrypted command packet ------------
    def build_command_packet(self, action, token, params=None, force_seq=None):
        """Encrypts + returns the wire packet. Does NOT talk to the hub —
        callers send this packet however they like (this lets the demo
        script simulate an attacker intercepting/replaying/tampering
        with it in transit)."""
        self.seq += 1
        seq = force_seq if force_seq is not None else self.seq
        msg = {"seq": seq, "action": action, "token": token, "params": params or {}}
        aad = self.device_id.encode()
        return cu.aes_encrypt(self.session_key, json.dumps(msg).encode(), associated_data=aad)

    def decrypt_response(self, packet):
        aad = f"{self.device_id}-resp".encode()
        plaintext = cu.aes_decrypt(self.session_key, packet, associated_data=aad)
        return json.loads(plaintext.decode())


class SmartLock(IoTDevice):
    role = "smart_lock"

    def __init__(self, device_id="lock-front-door"):
        super().__init__(device_id)
        self.locked = True

    def execute(self, action, params):
        if action == "unlock":
            self.locked = False
            return {"status": "unlocked"}
        if action == "lock":
            self.locked = True
            return {"status": "locked"}
        return {"status": "unknown_action"}


class SecurityCamera(IoTDevice):
    role = "security_camera"

    def execute(self, action, params):
        if action == "view_stream":
            return {"status": "streaming", "frame": "<binary-jpeg-frame>"}
        if action == "record_clip":
            return {"status": "recording", "duration": params.get("seconds", 10)}
        return {"status": "unknown_action"}


class MotionSensor(IoTDevice):
    role = "motion_sensor"

    def execute(self, action, params):
        if action == "read_sensor":
            return {"status": "ok", "motion_detected": False}
        return {"status": "unknown_action"}


class SmartLight(IoTDevice):
    role = "smart_light"

    def __init__(self, device_id="light-living-room"):
        super().__init__(device_id)
        self.is_on = False

    def execute(self, action, params):
        if action == "turn_on":
            self.is_on = True
            return {"status": "light_on"}
        if action == "turn_off":
            self.is_on = False
            return {"status": "light_off"}
        return {"status": "unknown_action"}

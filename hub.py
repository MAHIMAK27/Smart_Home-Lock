"""
hub.py
======
The Central Hub is the trust anchor of the smart home:
  - Acts as a Certificate Authority (CA): registers devices and issues
    them signed identity certificates.
  - Runs the secure handshake with each device (ECDH + challenge/response
    authentication) to establish a private, authenticated session.
  - Enforces access control: every command must carry a valid,
    non-expired, correctly-scoped access token.
  - Enforces replay protection via a strictly increasing per-session
    sequence number.
"""

import os
import time
import json

import crypto_utils as cu


class SecurityError(Exception):
    """Raised for any authentication / integrity / authorization failure."""


class Session:
    def __init__(self, device_id: str, session_key: bytes):
        self.device_id = device_id
        self.session_key = session_key
        self.last_seq = -1          # replay protection
        self.created_at = time.time()


class Hub:
    def __init__(self, name="home-hub-01", verbose=True):
        self.name = name
        self.verbose = verbose
        # CA identity used to sign device certificates
        self.ca_private, self.ca_public = cu.generate_identity_keypair()
        # Symmetric secret used to HMAC-sign access tokens
        self.hub_secret = os.urandom(32)
        # device_id -> certificate (issued at registration/provisioning time)
        self.registered_devices = {}
        # device_id -> Session (populated after a successful handshake)
        self.sessions = {}
        self.log = []

    # ---- logging -------------------------------------------------------
    def _log(self, msg, ok=True):
        entry = f"{'OK ' if ok else 'REJECT'}  [{self.name}] {msg}"
        self.log.append(entry)
        if self.verbose:
            print(entry)

    # ---- provisioning (factory / setup time, done once per device) ----
    def register_device(self, device_id: str, device_identity_pub, role: str):
        cert = cu.issue_certificate(self.ca_private, device_id, device_identity_pub, role)
        self.registered_devices[device_id] = cert
        self._log(f"registered device '{device_id}' (role={role}), certificate issued")
        return cert

    # ---- handshake: Secure-the-Channel + Authenticate stages ----------
    def handshake_step1_receive_hello(self, device_id, cert, device_ecdh_pub_bytes):
        """
        Verify the device's certificate. Returns a challenge nonce + the
        hub's own ephemeral ECDH public key, or raises SecurityError.
        """
        if not cu.verify_certificate(self.ca_public, cert):
            self._log(f"HELLO from '{device_id}': invalid/expired/unknown certificate", ok=False)
            raise SecurityError("certificate verification failed — device not trusted")

        if cert["body"]["device_id"] != device_id:
            self._log(f"HELLO from '{device_id}': device_id does not match certificate", ok=False)
            raise SecurityError("device_id / certificate mismatch")

        hub_ecdh_priv, hub_ecdh_pub = cu.generate_ecdh_keypair()
        challenge = os.urandom(16)

        # stash pending handshake state
        self._pending = getattr(self, "_pending", {})
        self._pending[device_id] = {
            "cert": cert,
            "device_ecdh_pub_bytes": device_ecdh_pub_bytes,
            "hub_ecdh_priv": hub_ecdh_priv,
            "challenge": challenge,
        }
        self._log(f"HELLO from '{device_id}': certificate valid, issuing challenge")
        return challenge, cu.raw_public_bytes(hub_ecdh_pub)

    def handshake_step2_verify_response(self, device_id, signature_b64):
        """
        Verify the device signed our challenge with the private key that
        matches the certificate we already validated. On success, derive
        the shared session key.
        """
        pending = self._pending.get(device_id)
        if pending is None:
            raise SecurityError("no pending handshake for this device")

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64
        device_identity_pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(pending["cert"]["body"]["public_key"])
        )

        if not cu.verify_challenge(device_identity_pub, pending["challenge"], signature_b64):
            self._log(f"CHALLENGE-RESPONSE from '{device_id}': signature invalid", ok=False)
            raise SecurityError("challenge signature invalid — possible impostor")

        session_key = cu.derive_session_key(
            pending["hub_ecdh_priv"],
            pending["device_ecdh_pub_bytes"],
            context=f"{self.name}|{device_id}".encode(),
        )
        self.sessions[device_id] = Session(device_id, session_key)
        del self._pending[device_id]
        self._log(f"CHALLENGE-RESPONSE from '{device_id}': verified. Secure session established")
        return True

    # ---- authorization: issue a scoped, short-lived access token ------
    def issue_token(self, device_id, scopes, ttl_seconds=60):
        token = cu.issue_access_token(self.hub_secret, device_id, scopes, ttl_seconds)
        self._log(f"issued access token to '{device_id}' scopes={scopes} ttl={ttl_seconds}s")
        return token

    # ---- receiving an encrypted, authorized command from a device -----
    def receive_command(self, device_id, packet):
        session = self.sessions.get(device_id)
        if session is None:
            self._log(f"COMMAND from '{device_id}': no established session", ok=False)
            raise SecurityError("no secure session — handshake required first")

        aad = device_id.encode()
        try:
            plaintext = cu.aes_decrypt(session.session_key, packet, associated_data=aad)
        except Exception:
            self._log(f"COMMAND from '{device_id}': AES-GCM auth tag invalid (tampered ciphertext)", ok=False)
            raise SecurityError("message integrity check failed — packet was tampered with or key mismatch")

        msg = json.loads(plaintext.decode())

        # --- replay protection ---
        seq = msg["seq"]
        if seq <= session.last_seq:
            self._log(f"COMMAND from '{device_id}': sequence {seq} <= last seen {session.last_seq} (REPLAY)", ok=False)
            raise SecurityError("replay detected — sequence number already used")

        # --- access control: verify the capability token ---
        ok, reason = cu.verify_access_token(self.hub_secret, msg["token"], msg["action"])
        if not ok:
            self._log(f"COMMAND from '{device_id}' action='{msg['action']}': access denied ({reason})", ok=False)
            raise SecurityError(f"access denied: {reason}")

        session.last_seq = seq
        self._log(f"COMMAND from '{device_id}': action='{msg['action']}' seq={seq} accepted")
        return msg["action"], msg.get("params", {})

    def handle_and_execute(self, device_obj, packet):
        """Convenience used by the demo: decrypt+authorize the packet,
        run the action on the (simulated) physical device, encrypt the
        response. Raises SecurityError if the packet is rejected."""
        action, params = self.receive_command(device_obj.device_id, packet)
        result = device_obj.execute(action, params)
        return self.send_response(device_obj.device_id, result)

    def send_response(self, device_id, response_obj):
        session = self.sessions[device_id]
        aad = f"{device_id}-resp".encode()
        packet = cu.aes_encrypt(session.session_key, json.dumps(response_obj).encode(), associated_data=aad)
        return packet

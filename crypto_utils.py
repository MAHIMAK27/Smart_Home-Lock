"""
crypto_utils.py
================
Core cryptographic primitives used across the IoT Smart Home Security
framework.

Techniques used (and why):
  - X25519 (ECDH)      -> establishes a shared secret between a device and
                           the hub over an untrusted channel (Secure the
                           Channel stage). Forward secrecy: a fresh key
                           pair is generated for every session.
  - HKDF-SHA256         -> derives a uniform 256-bit AES session key from
                           the raw ECDH shared secret.
  - AES-256-GCM (AEAD)  -> encrypts + authenticates every message on the
                           channel. GCM gives us confidentiality AND
                           integrity/tamper-detection in one primitive.
  - Ed25519             -> device identity. Every device holds a signing
                           keypair; the Hub acts as a small Certificate
                           Authority (CA) and signs each device's public
                           key. This is what lets the Hub *authenticate*
                           a device (and reject impostors) instead of
                           merely encrypting traffic with it.
  - HMAC-SHA256         -> signs short-lived access tokens (capability
                           tokens) used for the Control Access stage.
"""

import os
import time
import json
import base64
import hashlib
import hmac as hmac_module

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def raw_public_bytes(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# --------------------------------------------------------------------------
# ECDH key exchange + session key derivation  (Secure-the-Channel stage)
# --------------------------------------------------------------------------

def generate_ecdh_keypair():
    """Fresh, ephemeral X25519 keypair for one session (forward secrecy)."""
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def derive_session_key(my_private: X25519PrivateKey,
                        their_public_bytes: bytes,
                        context: bytes) -> bytes:
    """
    Run ECDH then HKDF-SHA256 to get a 32-byte AES-256 key.
    `context` binds the key to the two device IDs so a key derived for
    one conversation can't be replayed as another (e.g. b"hub|lock-01").
    """
    their_public = X25519PublicKey.from_public_bytes(their_public_bytes)
    shared_secret = my_private.exchange(their_public)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"iot-smart-home-session-key|" + context,
    ).derive(shared_secret)


# --------------------------------------------------------------------------
# AES-256-GCM authenticated encryption  (used for every message on the wire)
# --------------------------------------------------------------------------

def aes_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return {"nonce": b64(nonce), "ciphertext": b64(ct)}


def aes_decrypt(key: bytes, packet: dict, associated_data: bytes = b"") -> bytes:
    nonce = base64.b64decode(packet["nonce"])
    ct = base64.b64decode(packet["ciphertext"])
    # Raises InvalidTag if the packet was tampered with or the key is wrong.
    return AESGCM(key).decrypt(nonce, ct, associated_data)


# --------------------------------------------------------------------------
# Ed25519 device identity + Hub-as-CA certificates  (Authenticate stage)
# --------------------------------------------------------------------------

def generate_identity_keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def issue_certificate(ca_private: Ed25519PrivateKey, device_id: str,
                       device_pub: Ed25519PublicKey, role: str,
                       valid_seconds: int = 3600) -> dict:
    """
    The Hub (acting as CA) signs a small certificate binding a device_id
    to its public key and role. Devices present this cert during the
    handshake; the Hub verifies it against its own CA public key so a
    rogue / unregistered device (which has no valid certificate) is
    rejected outright.
    """
    body = {
        "device_id": device_id,
        "public_key": b64(raw_public_bytes(device_pub)),
        "role": role,
        "issued_at": time.time(),
        "expires_at": time.time() + valid_seconds,
    }
    body_bytes = json.dumps(body, sort_keys=True).encode()
    signature = ca_private.sign(body_bytes)
    return {"body": body, "signature": b64(signature)}


def verify_certificate(ca_public: Ed25519PublicKey, cert: dict) -> bool:
    body_bytes = json.dumps(cert["body"], sort_keys=True).encode()
    signature = base64.b64decode(cert["signature"])
    try:
        ca_public.verify(signature, body_bytes)
    except InvalidSignature:
        return False
    if time.time() > cert["body"]["expires_at"]:
        return False
    return True


def sign_challenge(private_key: Ed25519PrivateKey, challenge: bytes) -> str:
    return b64(private_key.sign(challenge))


def verify_challenge(public_key: Ed25519PublicKey, challenge: bytes, signature_b64: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64), challenge)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# HMAC-signed, time-limited capability tokens  (Control Access stage)
# --------------------------------------------------------------------------

def issue_access_token(hub_secret: bytes, device_id: str, scopes: list,
                        ttl_seconds: int = 60) -> dict:
    """
    A capability token: "this holder may call these specific actions on
    this specific device until this time". Short TTL limits the damage
    of a leaked token. HMAC (not just trust) means a device can verify
    a token it receives was really issued by the Hub, without needing
    a database round-trip.
    """
    payload = {
        "device_id": device_id,
        "scopes": scopes,
        "issued_at": time.time(),
        "expires_at": time.time() + ttl_seconds,
        "nonce": b64(os.urandom(8)),  # prevents identical tokens colliding
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    mac = hmac_module.new(hub_secret, payload_bytes, hashlib.sha256).hexdigest()
    return {"payload": payload, "mac": mac}


def verify_access_token(hub_secret: bytes, token: dict, required_scope: str) -> tuple:
    """Returns (ok: bool, reason: str)."""
    payload_bytes = json.dumps(token["payload"], sort_keys=True).encode()
    expected = hmac_module.new(hub_secret, payload_bytes, hashlib.sha256).hexdigest()
    if not hmac_module.compare_digest(expected, token["mac"]):
        return False, "invalid token signature (forged or corrupted token)"
    if time.time() > token["payload"]["expires_at"]:
        return False, "token expired"
    if required_scope not in token["payload"]["scopes"]:
        return False, f"token does not grant scope '{required_scope}'"
    return True, "ok"

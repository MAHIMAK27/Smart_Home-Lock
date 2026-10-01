import json
import time
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from hub import Hub, SecurityError
from devices import SmartLock, SmartLight
import crypto_utils as cu


# ============================================================
# SMART HOME SECURITY SYSTEM
# Existing cryptographic logic is NOT modified.
# This file only provides a local browser interface.
# ============================================================

class WebState:

    def __init__(self):
        self.reset()

    def reset(self):
        # Use the existing Hub and Device implementations
        self.hub = Hub(verbose=False)

        self.lock = SmartLock("lock-front-door")
        self.light = SmartLight("light-living-room")

        # Provision + secure handshake
        for device in (self.lock, self.light):
            device.register_with_hub(self.hub)
            device.connect(self.hub)

        # Last packet used for attack demonstrations
        self.last_device = None
        self.last_packet = None
        self.last_token = None

        self.events = []

        self.add_event(
            "SYSTEM",
            "Smart Home Security System initialized",
            True
        )

        self.add_event(
            "AUTH",
            "Smart Lock certificate verified and secure session established",
            True
        )

        self.add_event(
            "AUTH",
            "Smart Light certificate verified and secure session established",
            True
        )

    def add_event(self, category, message, success=True):
        self.events.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "category": category,
            "message": message,
            "success": success
        })

        # Keep UI log manageable
        self.events = self.events[:100]


state = WebState()

# UI-only trace of the most recent legitimate encryption/decryption flow.
# This does not change the cryptographic implementation.
state.last_crypto = {
    "ciphertext": None,
    "device": None,
    "action": None,
    "sequence": None,
    "authenticated": False,
    "decrypted": False
}


# ============================================================
# COMMAND PROCESSING
# ============================================================

def send_command(device, action, scopes, params=None):

    token = state.hub.issue_token(
        device.device_id,
        scopes=scopes,
        ttl_seconds=60
    )

    packet = device.build_command_packet(
        action,
        token,
        params
    )

    # Save packet for replay/tampering demonstrations
    state.last_device = device
    state.last_packet = packet
    state.last_token = token

    # Record UI-visible cryptographic trace (without exposing keys).
    state.last_crypto = {
        "ciphertext": packet["ciphertext"],
        "device": device.device_id,
        "action": action,
        "sequence": device.seq,
        "authenticated": False,
        "decrypted": False
    }

    try:

        response_packet = state.hub.handle_and_execute(
            device,
            packet
        )

        response = device.decrypt_response(response_packet)

        state.last_crypto.update({
            "authenticated": True,
            "decrypted": True
        })

        state.add_event(
            "COMMAND",
            f"{device.device_id}: {action} → {response['status']}",
            True
        )

        return {
            "success": True,
            "device": device.device_id,
            "action": action,
            "response": response,
            "ciphertext": packet["ciphertext"][:60] + "...",
            "sequence": device.seq
        }

    except SecurityError as e:

        state.add_event(
            "SECURITY",
            str(e),
            False
        )

        return {
            "success": False,
            "error": str(e)
        }


# ============================================================
# ATTACK SIMULATIONS
# ============================================================

def attack_tamper():

    if state.last_packet is None:
        return {
            "success": False,
            "error": "Send a legitimate command first."
        }

    tampered = dict(state.last_packet)

    raw = bytearray(
        base64.b64decode(
            tampered["ciphertext"]
        )
    )

    # Flip one byte
    raw[0] ^= 0xFF

    tampered["ciphertext"] = base64.b64encode(
        bytes(raw)
    ).decode()

    try:

        state.hub.handle_and_execute(
            state.last_device,
            tampered
        )

        state.add_event(
            "ATTACK",
            "Tampered packet was unexpectedly accepted",
            False
        )

        return {
            "success": False,
            "error": "Tampered packet was accepted"
        }

    except SecurityError as e:

        state.add_event(
            "ATTACK",
            f"Tampering blocked: {e}",
            True
        )

        return {
            "success": True,
            "attack": "tamper",
            "message": str(e)
        }


def attack_replay():

    if state.last_packet is None:
        return {
            "success": False,
            "error": "Send a legitimate command first."
        }

    try:

        state.hub.handle_and_execute(
            state.last_device,
            state.last_packet
        )

        state.add_event(
            "ATTACK",
            "Replay attack was unexpectedly accepted",
            False
        )

        return {
            "success": False,
            "error": "Replay was accepted"
        }

    except SecurityError as e:

        state.add_event(
            "ATTACK",
            f"Replay blocked: {e}",
            True
        )

        return {
            "success": True,
            "attack": "replay",
            "message": str(e)
        }


def attack_rogue():

    rogue = SmartLock("lock-front-door")

    # Fake certificate
    rogue.cert = {
        "body": {
            "device_id": "lock-front-door",
            "public_key": cu.b64(
                cu.raw_public_bytes(
                    rogue.identity_pub
                )
            ),
            "role": "smart_lock",
            "issued_at": time.time(),
            "expires_at": time.time() + 3600
        },

        # Invalid signature
        "signature": cu.b64(
            b"\x00" * 64
        )
    }

    try:

        rogue.connect(state.hub)

        state.add_event(
            "ATTACK",
            "Rogue device was unexpectedly accepted",
            False
        )

        return {
            "success": False,
            "error": "Rogue device accepted"
        }

    except SecurityError as e:

        state.add_event(
            "ATTACK",
            f"Rogue device blocked: {e}",
            True
        )

        return {
            "success": True,
            "attack": "rogue",
            "message": str(e)
        }


def attack_wrong_scope():

    # Token only allows "lock"
    token = state.hub.issue_token(
        state.lock.device_id,
        scopes=["lock"],
        ttl_seconds=60
    )

    # Try to perform "unlock"
    packet = state.lock.build_command_packet(
        "unlock",
        token
    )

    try:

        state.hub.handle_and_execute(
            state.lock,
            packet
        )

        state.add_event(
            "ATTACK",
            "Privilege escalation unexpectedly succeeded",
            False
        )

        return {
            "success": False,
            "error": "Out-of-scope command accepted"
        }

    except SecurityError as e:

        state.add_event(
            "ATTACK",
            f"Wrong-scope command blocked: {e}",
            True
        )

        return {
            "success": True,
            "attack": "wrong_scope",
            "message": str(e)
        }


# ============================================================
# STATE FOR BROWSER
# ============================================================

def get_state():

    return {
        "lock": {
            "id": state.lock.device_id,
            "locked": state.lock.locked,
            "connected": state.lock.session_key is not None,
            "sequence": state.lock.seq
        },

        "light": {
            "id": state.light.device_id,
            "on": state.light.is_on,
            "connected": state.light.session_key is not None,
            "sequence": state.light.seq
        },

        "registered_devices": len(
            state.hub.registered_devices
        ),

        "secure_sessions": len(
            state.hub.sessions
        ),

        "last_crypto": {
            **state.last_crypto,
            "ciphertext": (
                state.last_crypto["ciphertext"][:96] + "..."
                if state.last_crypto["ciphertext"]
                else None
            )
        },

        "events": state.events
    }


# ============================================================
# HTML / CSS / JAVASCRIPT
# ============================================================

HTML = r"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>IoT Smart Home Security</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background:
        radial-gradient(circle at top right,
        #16233d 0,
        #080d18 40%,
        #050810 100%);
    color: #e8eefc;
    min-height: 100vh;
}

/* =========================================================
   HEADER
   ========================================================= */

.header {
    height: 80px;
    padding: 0 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #1d2940;
    background: rgba(5, 8, 16, 0.88);
    backdrop-filter: blur(15px);
}

.logo {
    display: flex;
    align-items: center;
    gap: 14px;
}

.logo-icon {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #10233a;
    font-size: 25px;
}

.logo h1 {
    margin: 0;
    font-size: 20px;
}

.logo p {
    margin: 4px 0 0;
    color: #73809b;
    font-size: 12px;
}

.status {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 9px 15px;
    border-radius: 20px;
    background: #0b2019;
    border: 1px solid #194b37;
    color: #52e3a4;
    font-size: 13px;
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #42e49c;
    box-shadow: 0 0 10px #42e49c;
}

/* =========================================================
   LAYOUT
   ========================================================= */

.container {
    padding: 32px 40px;
    max-width: 1500px;
    margin: auto;
}

.hero {
    margin-bottom: 30px;
}

.hero h2 {
    font-size: 32px;
    margin: 0 0 8px;
}

.hero p {
    margin: 0;
    color: #78859f;
}

/* =========================================================
   STATS
   ========================================================= */

.stats {
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 25px;
}

.stat {
    background: rgba(12, 18, 31, 0.82);
    border: 1px solid #1c2940;
    border-radius: 16px;
    padding: 20px;
}

.stat-label {
    color: #74819b;
    font-size: 13px;
}

.stat-value {
    margin-top: 9px;
    font-size: 27px;
    font-weight: bold;
}

/* =========================================================
   GRID
   ========================================================= */

.main-grid {
    display: grid;
    grid-template-columns:
        1.4fr 0.8fr;
    gap: 22px;
}

.panel {
    background: rgba(10, 16, 28, 0.88);
    border: 1px solid #1c2940;
    border-radius: 18px;
    padding: 24px;
}

.panel-title {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.panel-title h3 {
    margin: 0;
    font-size: 18px;
}

.panel-title span {
    color: #65728d;
    font-size: 12px;
}

/* =========================================================
   DEVICES
   ========================================================= */

.devices {
    display: grid;
    grid-template-columns:
        repeat(2, 1fr);
    gap: 16px;
}

.device {
    border: 1px solid #24324b;
    background: #0c1423;
    border-radius: 16px;
    padding: 20px;
}

.device-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.device-icon {
    font-size: 32px;
}

.device-name {
    margin-top: 15px;
    font-size: 17px;
    font-weight: bold;
}

.device-id {
    color: #65738e;
    font-size: 11px;
    margin-top: 5px;
}

.secure {
    color: #4ce2a1;
    font-size: 12px;
}

.state {
    margin: 18px 0;
    padding: 13px;
    border-radius: 10px;
    background: #08101d;
    color: #aebbd2;
}

.buttons {
    display: flex;
    gap: 8px;
}

button {
    border: 0;
    cursor: pointer;
    border-radius: 9px;
    padding: 10px 14px;
    color: white;
    background: #17263d;
    border: 1px solid #2a3b59;
    transition: 0.2s;
}

button:hover {
    background: #203451;
    transform: translateY(-1px);
}

button.primary {
    background: #116b65;
    border-color: #1a958d;
}

button.danger {
    background: #572330;
    border-color: #8f3c4d;
}

/* =========================================================
   SECURITY PIPELINE
   ========================================================= */

.pipeline {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.step {
    display: flex;
    align-items: center;
    gap: 13px;
    padding: 13px;
    border-radius: 11px;
    background: #0b1321;
    border: 1px solid #1c2940;
}

.step-icon {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: #10233a;
    display: flex;
    align-items: center;
    justify-content: center;
}

.step-text strong {
    display: block;
    font-size: 13px;
}

.step-text small {
    color: #697791;
}

/* =========================================================
   ATTACK LAB
   ========================================================= */

.attack-panel {
    margin-top: 22px;
}

.attack-grid {
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 12px;
}

.attack {
    text-align: left;
    min-height: 100px;
}

.attack .emoji {
    font-size: 23px;
    display: block;
    margin-bottom: 10px;
}

.attack strong {
    display: block;
}

.attack small {
    display: block;
    color: #73809a;
    margin-top: 5px;
}

/* =========================================================
   LOG
   ========================================================= */

.log-panel {
    margin-top: 22px;
}

.log {
    max-height: 330px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 7px;
}

.log-entry {
    display: grid;
    grid-template-columns:
        70px 90px 1fr;
    gap: 10px;
    padding: 11px 12px;
    background: #080f1b;
    border-radius: 8px;
    font-size: 12px;
}

.log-time {
    color: #596780;
}

.log-category {
    color: #56dca4;
}

.log-category.attack {
    color: #ff687e;
}

.log-category.command {
    color: #61b7ff;
}

.log-message {
    color: #9eabc2;
}

/* =========================================================
   FOOTER
   ========================================================= */

.footer {
    text-align: center;
    color: #4f5d75;
    font-size: 11px;
    margin: 28px 0;
}

/* =========================================================
   RESPONSIVE
   ========================================================= */

@media(max-width: 1000px) {

    .stats {
        grid-template-columns:
            repeat(2, 1fr);
    }

    .main-grid {
        grid-template-columns: 1fr;
    }

    .attack-grid {
        grid-template-columns:
            repeat(2, 1fr);
    }
}

/* Encryption / decryption trace */
.crypto-panel {
    margin-top: 24px;
}

.crypto-flow {
    display: grid;
    grid-template-columns: 1fr auto 1fr auto 1fr auto 1fr;
    gap: 12px;
    align-items: stretch;
}

.crypto-step {
    background: #0a1220;
    border: 1px solid #24334b;
    border-radius: 12px;
    padding: 16px;
    min-height: 105px;
    display: flex;
    flex-direction: column;
    gap: 6px;
}

.crypto-step strong {
    color: #eef4ff;
}

.crypto-step span {
    color: #8fa0ba;
    font-size: 13px;
    word-break: break-word;
}

.crypto-icon {
    font-size: 22px;
}

.crypto-arrow {
    display: flex;
    align-items: center;
    justify-content: center;
    color: #4ce2a1;
    font-size: 24px;
}

.crypto-details {
    margin-top: 14px;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    color: #aebbd0;
    font-size: 13px;
}

.crypto-details > div {
    background: #0a1220;
    border-radius: 9px;
    padding: 10px 12px;
}

@media(max-width: 900px) {
    .crypto-flow {
        grid-template-columns: 1fr;
    }

    .crypto-arrow {
        transform: rotate(90deg);
    }

    .crypto-details {
        grid-template-columns: 1fr 1fr;
    }
}

@media(max-width: 650px) {

    .container {
        padding: 20px;
    }

    .header {
        padding: 0 20px;
    }

    .devices {
        grid-template-columns: 1fr;
    }

    .stats {
        grid-template-columns: 1fr;
    }

    .attack-grid {
        grid-template-columns: 1fr;
    }
}

</style>

</head>


<body>


<header class="header">

    <div class="logo">

        <div class="logo-icon">
            🛡️
        </div>

        <div>

            <h1>
                IoT Smart Home Security
            </h1>

            <p>
                Cryptography & Network Security • BCS703
            </p>

        </div>

    </div>


    <div class="status">

        <span class="status-dot"></span>

        SECURE SYSTEM ONLINE

    </div>

</header>



<main class="container">


<section class="hero">

    <h2>
        Smart Home Security Dashboard 🏠
    </h2>

    <p>
        Monitor devices, execute authenticated commands,
        and simulate cybersecurity attacks.
    </p>

</section>



<!-- ======================================================
     STATISTICS
======================================================= -->

<section class="stats">

    <div class="stat">

        <div class="stat-label">
            🔌 Registered Devices
        </div>

        <div
            class="stat-value"
            id="registered"
        >
            0
        </div>

    </div>


    <div class="stat">

        <div class="stat-label">
            🔐 Secure Sessions
        </div>

        <div
            class="stat-value"
            id="sessions"
        >
            0
        </div>

    </div>


    <div class="stat">

        <div class="stat-label">
            🛡️ Security Status
        </div>

        <div
            class="stat-value"
            style="color:#4ce2a1"
        >
            PROTECTED
        </div>

    </div>


    <div class="stat">

        <div class="stat-label">
            🔑 Encryption
        </div>

        <div
            class="stat-value"
            style="font-size:20px"
        >
            AES-256-GCM
        </div>

    </div>

</section>



<div class="main-grid">


<!-- ======================================================
     DEVICES
======================================================= -->

<section class="panel">

    <div class="panel-title">

        <h3>
            🏠 Smart Devices
        </h3>

        <span>
            LIVE STATUS
        </span>

    </div>


    <div class="devices">


        <!-- SMART LOCK -->

        <div class="device">

            <div class="device-head">

                <div class="device-icon">
                    🔒
                </div>

                <div class="secure">
                    ● SECURE
                </div>

            </div>


            <div class="device-name">
                Smart Lock
            </div>

            <div
                class="device-id"
                id="lock-id"
            >
                lock-front-door
            </div>


            <div
                class="state"
                id="lock-state"
            >
                🔒 Locked
            </div>


            <div class="buttons">

                <button
                    class="primary"
                    onclick="sendCommand('lock','unlock')"
                >
                    🔓 Unlock
                </button>

                <button
                    onclick="sendCommand('lock','lock')"
                >
                    🔒 Lock
                </button>

            </div>

        </div>



        <!-- SMART LIGHT -->

        <div class="device">

            <div class="device-head">

                <div class="device-icon">
                    💡
                </div>

                <div class="secure">
                    ● SECURE
                </div>

            </div>


            <div class="device-name">
                Smart Light
            </div>

            <div
                class="device-id"
                id="light-id"
            >
                light-living-room
            </div>


            <div
                class="state"
                id="light-state"
            >
                💡 Off
            </div>


            <div class="buttons">

                <button
                    class="primary"
                    onclick="sendCommand('light','turn_on')"
                >
                    💡 Turn ON
                </button>

                <button
                    onclick="sendCommand('light','turn_off')"
                >
                    🌙 Turn OFF
                </button>

            </div>

        </div>


    </div>

</section>



<!-- ======================================================
     SECURITY PIPELINE
======================================================= -->

<section class="panel">

    <div class="panel-title">

        <h3>
            🔐 Security Pipeline
        </h3>

        <span>
            ACTIVE
        </span>

    </div>


    <div class="pipeline">


        <div class="step">

            <div class="step-icon">
                🪪
            </div>

            <div class="step-text">

                <strong>
                    Device Authentication
                </strong>

                <small>
                    Ed25519 Certificate
                </small>

            </div>

        </div>


        <div class="step">

            <div class="step-icon">
                🔄
            </div>

            <div class="step-text">

                <strong>
                    Secure Handshake
                </strong>

                <small>
                    X25519 ECDH + HKDF
                </small>

            </div>

        </div>


        <div class="step">

            <div class="step-icon">
                    🔐
            </div>

            <div class="step-text">

                <strong>
                    Message Encryption
                </strong>

                <small>
                    AES-256-GCM
                </small>

            </div>

        </div>


        <div class="step">

            <div class="step-icon">
                🎟️
            </div>

            <div class="step-text">

                <strong>
                    Access Control
                </strong>

                <small>
                    HMAC-SHA256 Tokens
                </small>

            </div>

        </div>


        <div class="step">

            <div class="step-icon">
                ♻️
            </div>

            <div class="step-text">

                <strong>
                    Replay Protection
                </strong>

                <small>
                    Sequence Numbers
                </small>

            </div>

        </div>


    </div>

</section>


</div>



<!-- ======================================================
     ATTACK LAB
======================================================= -->

<section class="panel attack-panel">

    <div class="panel-title">

        <h3>
            ⚔️ Cyber Attack Lab
        </h3>

        <span>
            SAFE SIMULATION
        </span>

    </div>


    <div class="attack-grid">


        <button
            class="attack danger"
            onclick="attack('tamper')"
        >

            <span class="emoji">
                🧬
            </span>

            <strong>
                Tampering
            </strong>

            <small>
                Modify encrypted packet
            </small>

        </button>


        <button
            class="attack danger"
            onclick="attack('replay')"
        >

            <span class="emoji">
                ♻️
            </span>

            <strong>
                Replay Attack
            </strong>

            <small>
                Resend old packet
            </small>

        </button>


        <button
            class="attack danger"
            onclick="attack('rogue')"
        >

            <span class="emoji">
                👤
            </span>

            <strong>
                Rogue Device
            </strong>

            <small>
                Fake certificate
            </small>

        </button>


        <button
            class="attack danger"
            onclick="attack('wrong_scope')"
        >

            <span class="emoji">
                🚫
            </span>

            <strong>
                Privilege Escalation
            </strong>

            <small>
                Invalid token scope
            </small>

        </button>


    </div>

</section>



<!-- ======================================================
     ENCRYPTION / DECRYPTION TRACE
======================================================= -->

<section class="panel crypto-panel">

    <div class="panel-title">
        <h3>
            🔐 Encryption / Decryption Trace
        </h3>

        <span>
            AES-256-GCM
        </span>
    </div>

    <div class="crypto-flow">
        <div class="crypto-step">
            <div class="crypto-icon">📝</div>
            <strong>Legitimate Command</strong>
            <span id="crypto-command">Waiting for command...</span>
        </div>

        <div class="crypto-arrow">→</div>

        <div class="crypto-step">
            <div class="crypto-icon">🔒</div>
            <strong>Encrypted Packet</strong>
            <span id="crypto-ciphertext">No packet yet</span>
        </div>

        <div class="crypto-arrow">→</div>

        <div class="crypto-step">
            <div class="crypto-icon">🔓</div>
            <strong>Hub Decryption</strong>
            <span id="crypto-decryption">Waiting...</span>
        </div>

        <div class="crypto-arrow">→</div>

        <div class="crypto-step">
            <div class="crypto-icon">✅</div>
            <strong>Authenticated Result</strong>
            <span id="crypto-result">Waiting...</span>
        </div>
    </div>

    <div class="crypto-details">
        <div><b>Algorithm:</b> AES-256-GCM</div>
        <div><b>Authentication:</b> <span id="crypto-auth">—</span></div>
        <div><b>Sequence:</b> <span id="crypto-seq">—</span></div>
        <div><b>Decrypted action:</b> <span id="crypto-action">—</span></div>
    </div>

</section>


<!-- ======================================================
     LIVE SECURITY LOG
======================================================= -->

<section class="panel log-panel">

    <div class="panel-title">

        <h3>
            📡 Security Event Log
        </h3>

        <span>
            LIVE
        </span>

    </div>


    <div
        class="log"
        id="log"
    >
    </div>

</section>



<div class="footer">

    IoT Smart Home Security •
    X25519 • HKDF-SHA256 •
    AES-256-GCM • Ed25519 •
    HMAC-SHA256

</div>


</main>



<script>

function showToast(message, ok = true) {
    let toast = document.getElementById("iot-toast");

    if (!toast) {
        toast = document.createElement("div");
        toast.id = "iot-toast";
        toast.style.cssText =
            "position:fixed;right:24px;bottom:24px;z-index:9999;" +
            "max-width:420px;padding:16px 18px;border-radius:12px;" +
            "font:14px Arial,sans-serif;line-height:1.45;" +
            "box-shadow:0 10px 30px rgba(0,0,0,.45);";
        document.body.appendChild(toast);
    }

    toast.style.background = ok ? "#0d3b2e" : "#4a1822";
    toast.style.border = ok ? "1px solid #2bd49b" : "1px solid #e85d75";
    toast.style.color = "#ffffff";
    toast.innerText = message;
    toast.style.display = "block";

    clearTimeout(window.__iotToastTimer);
    window.__iotToastTimer = setTimeout(() => {
        toast.style.display = "none";
    }, 3500);
}


async function post(url, data = {}) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache"
        },
        body: JSON.stringify(data)
    });

    const raw = await response.text();

    let result;
    try {
        result = JSON.parse(raw);
    } catch (e) {
        throw new Error(
            "Invalid server response (HTTP " +
            response.status + ")"
        );
    }

    if (!response.ok) {
        throw new Error(
            result.error || ("HTTP " + response.status)
        );
    }

    return result;
}


async function sendCommand(device, action) {
    const buttonLabel =
        device === "lock"
            ? (action === "unlock" ? "🔓 Unlock" : "🔒 Lock")
            : (action === "turn_on" ? "💡 Turn ON" : "🌙 Turn OFF");

    try {
        showToast("⏳ Processing " + buttonLabel + "...");

        const result = await post("/command", {
            device: device,
            action: action
        });

        if (result.success === true) {
            await refresh();

            const status =
                result.response && result.response.status
                    ? result.response.status
                    : "completed";

            showToast(
                "✅ " + buttonLabel + " authorized and executed\n" +
                "Device: " + result.device + "\n" +
                "Result: " + status,
                true
            );
        } else {
            await refresh();

            showToast(
                "❌ Command rejected\n" +
                (result.error || "Unknown security error"),
                false
            );
        }

    } catch (error) {
        console.error("COMMAND ERROR:", error);

        showToast(
            "❌ Command failed\n" +
            error.message,
            false
        );
    }
}


async function attack(type) {
    try {
        showToast("⏳ Running security attack simulation...");

        const result = await post("/attack", {
            type: type
        });

        await refresh();

        if (result.success === true) {
            showToast(
                "🛡️ ATTACK BLOCKED\n" +
                (result.message || "Security mechanism rejected the attack."),
                true
            );
        } else {
            showToast(
                "⚠️ " +
                (result.error || "Attack simulation failed."),
                false
            );
        }

    } catch (error) {
        console.error("ATTACK ERROR:", error);

        showToast(
            "❌ Attack request failed\n" +
            error.message,
            false
        );
    }
}


async function refresh() {

    try {

        const response =
            await fetch("/state");

        const data =
            await response.json();


        /* Stats */

        document.getElementById(
            "registered"
        ).innerText =
            data.registered_devices;


        document.getElementById(
            "sessions"
        ).innerText =
            data.secure_sessions;


        /* Lock */

        document.getElementById(
            "lock-id"
        ).innerText =
            data.lock.id;


        document.getElementById(
            "lock-state"
        ).innerText =
            data.lock.locked
                ? "🔒 Locked"
                : "🔓 Unlocked";


        /* Light */

        document.getElementById(
            "light-id"
        ).innerText =
            data.light.id;


        document.getElementById(
            "light-state"
        ).innerText =
            data.light.on
                ? "💡 ON"
                : "🌙 OFF";


        /* Encryption / Decryption Trace */
        const crypto = data.last_crypto || {};

        document.getElementById("crypto-command").innerText =
            crypto.action
                ? (crypto.device + " → " + crypto.action)
                : "Waiting for command...";

        document.getElementById("crypto-ciphertext").innerText =
            crypto.ciphertext || "No packet yet";

        document.getElementById("crypto-decryption").innerText =
            crypto.decrypted
                ? "✓ Packet decrypted successfully"
                : (crypto.ciphertext ? "Waiting for Hub..." : "Waiting...");

        document.getElementById("crypto-result").innerText =
            crypto.decrypted
                ? "✓ Command authenticated and executed"
                : "Waiting...";

        document.getElementById("crypto-auth").innerText =
            crypto.authenticated ? "✓ Valid" : "—";

        document.getElementById("crypto-seq").innerText =
            crypto.sequence != null ? crypto.sequence : "—";

        document.getElementById("crypto-action").innerText =
            crypto.decrypted && crypto.action ? crypto.action : "—";


        /* Logs */

        const log =
            document.getElementById("log");

        log.innerHTML = "";


        data.events.forEach(
            event => {

                const row =
                    document.createElement(
                        "div"
                    );

                row.className =
                    "log-entry";


                let categoryClass =
                    "";

                if (
                    event.category ===
                    "ATTACK"
                ) {
                    categoryClass =
                        "attack";
                }

                if (
                    event.category ===
                    "COMMAND"
                ) {
                    categoryClass =
                        "command";
                }


                row.innerHTML = `

                    <div class="log-time">
                        ${event.time}
                    </div>

                    <div
                        class="log-category
                        ${categoryClass}"
                    >
                        ${event.category}
                    </div>

                    <div class="log-message">
                        ${event.success ? "✓ " : "✕ "}
                        ${event.message}
                    </div>

                `;


                log.appendChild(row);

            }
        );


    } catch (error) {

        console.error(error);

    }

}


/* Refresh dashboard every second */

setInterval(
    refresh,
    1000
);


/* Initial load */

refresh();

</script>


</body>

</html>
"""


# ============================================================
# LOCAL BROWSER SERVER
# ============================================================

class WebHandler(BaseHTTPRequestHandler):

    def send_json(self, data, status=200):

        payload = json.dumps(
            data
        ).encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )
        self.send_header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0"
        )

        self.send_header(
            "Content-Length",
            str(len(payload))
        )

        self.end_headers()

        self.wfile.write(payload)


    def send_html(self):

        payload = HTML.encode(
            "utf-8"
        )

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.send_header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0"
        )

        self.send_header(
            "Content-Length",
            str(len(payload))
        )

        self.end_headers()

        self.wfile.write(payload)


    def read_json(self):

        length = int(
            self.headers.get(
                "Content-Length",
                0
            )
        )

        body = self.rfile.read(
            length
        )

        if not body:
            return {}

        return json.loads(
            body.decode("utf-8")
        )


    def do_GET(self):

        path = urlparse(
            self.path
        ).path

        if path == "/":
            self.send_html()

        elif path == "/state":
            self.send_json(
                get_state()
            )

        else:
            self.send_json(
                {"error": "Not found"},
                404
            )


    def do_POST(self):

        path = urlparse(
            self.path
        ).path

        try:

            data = self.read_json()


            # ------------------------------------------------
            # COMMAND
            # ------------------------------------------------

            if path == "/command":

                device_name =data.get("device")


                action = data.get("action")


                if device_name == "lock":

                    result = send_command(
                        state.lock,
                        action,
                        scopes=[
                            "unlock",
                            "lock"
                        ]
                    )

                elif device_name == "light":

                    result = send_command(
                        state.light,
                        action,
                        scopes=[
                            "turn_on",
                            "turn_off"
                        ]
                    )

                else:

                    result = {
                        "success": False,
                        "error":
                            "Unknown device"
                    }


                self.send_json(result)

                return


            # ------------------------------------------------
            # ATTACK
            # ------------------------------------------------

            if path == "/attack":

                attack_type =data.get("type")


                if attack_type == "tamper":

                    result =attack_tamper()


                elif attack_type == "replay":

                    result =attack_replay()


                elif attack_type == "rogue":

                    result =attack_rogue()


                elif attack_type == "wrong_scope":

                    result = attack_wrong_scope()


                else:

                    result = {
                        "success": False,
                        "error":
                            "Unknown attack"
                    }


                self.send_json(result)

                return


            self.send_json(
                {"error": "Not found"},
                404
            )


        except Exception as e:

            self.send_json(
                {
                    "success": False,
                    "error": str(e)
                },
                500
            )


    def log_message(
        self,
        format,
        *args
    ):
        # Keep terminal clean
        pass


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    HOST = "127.0.0.1"
    PORT = 8000

    print()
    print("=" * 60)
    print("   IoT SMART HOME SECURITY")
    print("   Browser Interface")
    print("=" * 60)
    print()
    print("🔐 Cryptography : ACTIVE")
    print("🛡️ Security     : ACTIVE")
    print("🏠 Devices      : 2")
    print()
    print(
        f"🌐 Open browser: http://{HOST}:{PORT}"
    )
    print()
    print("Press CTRL+C to stop.")
    print("=" * 60)
    print()

    server = HTTPServer(
        (HOST, PORT),
        WebHandler
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:

        print("\nServer stopped.")

        server.server_close()
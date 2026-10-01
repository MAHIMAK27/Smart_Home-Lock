# IoT Smart Home Security — Reference Implementation

Cryptography & Network Security (BCS703) — implementation of the secure
communication / authentication / access-control framework described in
the case study.

## Run

```
pip install cryptography
python3 web_ui.py             # BEST FOR VIVA — browser dashboard, then open http://127.0.0.1:8000
python3 interactive_demo.py   # terminal live demo — type commands, trigger attacks on demand
python3 demo.py                # scripted walkthrough, pauses between each step (add --auto to skip pauses)
python3 benchmark.py           # performance numbers (handshake / AES-GCM / tokens) — don't run this one live, it's verbose
```

## Files

- `crypto_utils.py` — ECDH (X25519), HKDF, AES-256-GCM, Ed25519 signatures,
  certificate issuance/verification, HMAC access tokens.
- `hub.py` — the Central Hub: acts as CA, runs the handshake, enforces
  replay protection and token-scope checks.
- `devices.py` — SmartLock / SmartLight / SecurityCamera / MotionSensor device logic.
- `web_ui.py` — **use this one for the viva/seminar.** Local browser
  dashboard (no external dependencies beyond `cryptography`): click
  Unlock/Lock/Turn ON/Turn OFF to send real authenticated+encrypted
  commands, watch the encryption/decryption trace panel fill in live,
  and click the four attack cards (Tampering, Replay, Rogue Device,
  Privilege Escalation) to watch the Hub reject each one in real time.
  Uses the exact same `hub.py` / `devices.py` / `crypto_utils.py` as
  everything else — the UI doesn't change the cryptography at all.
- `interactive_demo.py` — terminal alternative: menu-driven, send a
  real command to the lock or light and watch it get encrypted, sent,
  and executed step by step; or trigger an attack on demand.
- `demo.py` — scripted end-to-end run: provisioning, handshake, legitimate
  commands, then 6 attack simulations. Pauses before each step by default
  (press Enter to advance) — run with `--auto` to print straight through.
- `benchmark.py` — timing of each cryptographic operation.

See `IoT_Smart_Home_Security_Report.docx` for the full write-up (case
study, problem statement, proposed solution, implementation details,
results, and key observations).

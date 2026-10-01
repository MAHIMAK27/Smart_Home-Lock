"""
benchmark.py
============
Measures the practical cost of the crypto operations, to show the scheme
is lightweight enough for resource-constrained IoT devices.
"""

import time
import statistics as stats

from hub import Hub
from devices import SmartLock
import crypto_utils as cu


def timeit(fn, n=200):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)  # ms
    return {
        "mean_ms": round(stats.mean(times), 4),
        "p95_ms": round(sorted(times)[int(0.95 * len(times)) - 1], 4),
        "min_ms": round(min(times), 4),
    }


def main():
    hub = Hub()
    lock = SmartLock("lock-bench")
    lock.register_with_hub(hub)

    print("Handshake (ECDH + Ed25519 challenge-response), full round trip:")
    def full_handshake():
        d = SmartLock(f"lock-bench")
        d.identity_priv, d.identity_pub = lock.identity_priv, lock.identity_pub
        d.cert = lock.cert
        d.connect(hub)
    print(" ", timeit(full_handshake, n=100))

    lock.connect(hub)
    token = hub.issue_token(lock.device_id, scopes=["lock", "unlock"], ttl_seconds=3600)

    print("\nAES-256-GCM encrypt+decrypt of a 256-byte command payload:")
    payload = b"x" * 256
    def enc_dec():
        pkt = cu.aes_encrypt(lock.session_key, payload, associated_data=b"bench")
        cu.aes_decrypt(lock.session_key, pkt, associated_data=b"bench")
    print(" ", timeit(enc_dec, n=1000))

    print("\nFull authorized command round trip (encrypt, hub verify+decrypt+execute, encrypt response, decrypt):")
    def full_command():
        nonlocal_token = hub.issue_token(lock.device_id, scopes=["lock"], ttl_seconds=3600)
        pkt = lock.build_command_packet("lock", nonlocal_token)
        resp_pkt = hub.handle_and_execute(lock, pkt)
        lock.decrypt_response(resp_pkt)
    print(" ", timeit(full_command, n=200))

    print("\nCertificate issuance (Ed25519 sign) and verification:")
    print("  issue:  ", timeit(lambda: cu.issue_certificate(hub.ca_private, "bench-dev", lock.identity_pub, "smart_lock"), n=500))
    cert = cu.issue_certificate(hub.ca_private, "bench-dev", lock.identity_pub, "smart_lock")
    print("  verify: ", timeit(lambda: cu.verify_certificate(hub.ca_public, cert), n=500))


if __name__ == "__main__":
    main()

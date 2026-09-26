#!/usr/bin/env python3
"""Generates signature and RSA-OAEP test vectors with the OpenSSL CLI.

Python standard library + `openssl` (3.x) only. Writes
test/fixtures/vectors/openssl_vectors.json:

  - RSA-2048 PKCS#1 v1.5 signatures with SHA-256/384/512
  - ECDSA P-256/SHA-256 (low-S and high-S), P-256/SHA-384, P-384/SHA-384
  - RSA-OAEP SHA-256 ciphertexts with MGF1-SHA-1 (Android keystore) and
    MGF1-SHA-256 (Apple)

Usage: python3 tool/gen_vectors.py [path/to/openssl]
"""

import base64
import json
import os
import subprocess
import sys
import tempfile

OPENSSL = sys.argv[1] if len(sys.argv) > 1 else "openssl"
OUT = os.path.join(os.path.dirname(__file__), "..", "test", "fixtures", "vectors", "openssl_vectors.json")
P256_N = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

MESSAGE = b"biometric_signature: server-side verification vector"
OAEP_PLAINTEXT = "RSA-OAEP vector encrypted by openssl pkeyutl"


def run(*args, stdin=None):
    return subprocess.run([OPENSSL, *args], input=stdin, check=True, capture_output=True).stdout


def b64(data):
    return base64.b64encode(data).decode()


def der_len(n):
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def der_int(v):
    raw = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + der_len(len(raw)) + raw


def read_len(buf, i):
    first = buf[i]
    if first < 0x80:
        return first, i + 1
    count = first & 0x7F
    return int.from_bytes(buf[i + 1 : i + 1 + count], "big"), i + 1 + count


def parse_ecdsa(sig):
    assert sig[0] == 0x30
    _, i = read_len(sig, 1)
    values = []
    for _ in range(2):
        assert sig[i] == 0x02
        n, i = read_len(sig, i + 1)
        values.append(int.from_bytes(sig[i : i + n], "big"))
        i += n
    return values


def ecdsa_der(r, s):
    body = der_int(r) + der_int(s)
    return b"\x30" + der_len(len(body)) + body


def main():
    with tempfile.TemporaryDirectory() as tmp:
        def path(name):
            return os.path.join(tmp, name)

        run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path("rsa.pem"))
        run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path("p256.pem"))
        run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", path("p384.pem"))
        with open(path("msg.bin"), "wb") as f:
            f.write(MESSAGE)

        def spki(key):
            return run("pkey", "-in", path(key), "-pubout", "-outform", "DER")

        def pkcs8(key):
            return run("pkey", "-in", path(key), "-outform", "DER")

        def sign(key, digest):
            return run("dgst", f"-{digest}", "-sign", path(key), path("msg.bin"))

        def verify(key, digest, sig):
            with open(path("sig.bin"), "wb") as f:
                f.write(sig)
            run("dgst", f"-{digest}", "-verify", path(key + ".pub"), "-signature", path("sig.bin"), path("msg.bin"))

        for key in ("rsa.pem", "p256.pem", "p384.pem"):
            run("pkey", "-in", path(key), "-pubout", "-out", path(key + ".pub"))

        # Find one low-S and one high-S P-256 signature.
        low = high = None
        while low is None or high is None:
            sig = sign("p256.pem", "sha256")
            r, s = parse_ecdsa(sig)
            if s > P256_N // 2:
                high = high or sig
            else:
                low = low or sig
        verify("p256.pem", "sha256", high)

        signatures = {
            "rsa_sha256": sign("rsa.pem", "sha256"),
            "rsa_sha384": sign("rsa.pem", "sha384"),
            "rsa_sha512": sign("rsa.pem", "sha512"),
            "p256_sha256_lowS": low,
            "p256_sha256_highS": high,
            "p256_sha384": sign("p256.pem", "sha384"),
            "p384_sha384": sign("p384.pem", "sha384"),
        }

        def oaep(mgf1):
            with open(path("plain.txt"), "wb") as f:
                f.write(OAEP_PLAINTEXT.encode())
            return run(
                "pkeyutl", "-encrypt", "-pubin", "-inkey", path("rsa.pem.pub"), "-in", path("plain.txt"),
                "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", f"rsa_mgf1_md:{mgf1}",
            )

        out = {
            "generator": "tool/gen_vectors.py (" + run("version").decode().strip() + ")",
            "message": b64(MESSAGE),
            "keys": {
                "rsa2048": {"spki": b64(spki("rsa.pem")), "pkcs8": b64(pkcs8("rsa.pem"))},
                "p256": {"spki": b64(spki("p256.pem")), "pkcs8": b64(pkcs8("p256.pem"))},
                "p384": {"spki": b64(spki("p384.pem")), "pkcs8": b64(pkcs8("p384.pem"))},
            },
            "signatures": {name: b64(sig) for name, sig in signatures.items()},
            "oaep": {
                "plaintext": OAEP_PLAINTEXT,
                "mgf1_sha1": b64(oaep("sha1")),
                "mgf1_sha256": b64(oaep("sha256")),
            },
        }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print("wrote", os.path.normpath(OUT))


if __name__ == "__main__":
    main()

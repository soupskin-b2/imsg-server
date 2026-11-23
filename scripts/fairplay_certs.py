#!/usr/bin/env python3
"""Normalizes FairPlay cert chains + private keys into rustpush's `certs/fairplay` layout.

rustpush (src/activation.rs) embeds 10 slots `<slot>.crt` / `<slot>.pem`:
  <slot>.crt  concatenated DER certificate chain, leaf first, ending at Apple Root CA
              (sent verbatim to albert.apple.com as FairPlayCertChain)
  <slot>.pem  despite the name, a raw DER private key (loaded with PKey::private_key_from_der)

Source directory layout (any mix):
  <slot>.crt + <slot>.{key,pem,der}      cert chain + key for one slot
  fairplay.crt + fairplay.{key,pem,der}  default pair used for every slot without its own
  chain.{crt,pem,cer}                    optional intermediate/root certs, appended to any chain
                                         that does not already end at a self-signed root

Certificates and keys may each be PEM or DER. Each pair is checked: the key must match the leaf
certificate and the chain must verify up to a self-signed root (expiry is ignored, as Albert
ignores it). Requires the `openssl` CLI.

Usage: fairplay_certs.py SRC_DIR DEST_DIR
"""
import os
import re
import subprocess
import sys
import tempfile

SLOTS = [
    "4056631661436364584235346952193", "4056631661436364584235346952194",
    "4056631661436364584235346952195", "4056631661436364584235346952196",
    "4056631661436364584235346952197", "4056631661436364584235346952198",
    "4056631661436364584235346952199", "4056631661436364584235346952200",
    "4056631661436364584235346952201", "4056631661436364584235346952208",
]
KEY_EXTS = (".key", ".pem", ".der")
CHAIN_NAMES = ("chain.crt", "chain.pem", "chain.cer")
PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.S
)


class SetupError(Exception):
    pass


def openssl(args, data=None):
    res = subprocess.run(["openssl", *args], input=data, capture_output=True)
    if res.returncode != 0:
        raise SetupError(f"openssl {' '.join(args)} failed: {res.stderr.decode().strip()}")
    return res.stdout


def split_der(data, what):
    """Splits concatenated DER SEQUENCEs."""
    out, i = [], 0
    while i < len(data):
        if data[i] != 0x30 or i + 2 > len(data):
            raise SetupError(f"{what}: not a DER certificate sequence at byte {i}")
        first = data[i + 1]
        if first & 0x80:
            n = first & 0x7F
            if n == 0 or n > 4 or i + 2 + n > len(data):
                raise SetupError(f"{what}: bad DER length at byte {i}")
            length, hdr = int.from_bytes(data[i + 2:i + 2 + n], "big"), 2 + n
        else:
            length, hdr = first, 2
        end = i + hdr + length
        if end > len(data):
            raise SetupError(f"{what}: truncated DER certificate at byte {i}")
        out.append(data[i:end])
        i = end
    return out


def read_certs(path):
    data = open(path, "rb").read()
    if b"-----BEGIN" in data:
        blocks = PEM_CERT_RE.findall(data)
        if not blocks:
            raise SetupError(f"{path}: PEM file contains no CERTIFICATE blocks")
        return [
            openssl(
                ["x509", "-outform", "DER"],
                b"-----BEGIN CERTIFICATE-----\n" + b + b"\n-----END CERTIFICATE-----\n",
            )
            for b in blocks
        ]
    certs = split_der(data, path)
    if not certs:
        raise SetupError(f"{path}: empty certificate file")
    return certs


def cert_field(der, field):
    out = openssl(["x509", "-inform", "DER", "-noout", f"-{field}", "-nameopt", "RFC2253"], der)
    return out.decode().strip().split("=", 1)[1]


def read_key_der(path):
    data = open(path, "rb").read()
    inform = "PEM" if b"-----BEGIN" in data else "DER"
    # PKey::private_key_from_der accepts both PKCS#1 and PKCS#8.
    for args in (
        ["rsa", "-traditional"],  # OpenSSL 3: PKCS#1, like upstream's legacy key
        ["rsa"],  # OpenSSL 1.1: PKCS#1 by default
        ["pkey"],  # non-RSA keys: PKCS#8
    ):
        try:
            return openssl([*args, "-inform", inform, "-outform", "DER"], data)
        except SetupError as e:
            err = e
    raise SetupError(f"{path}: cannot read private key ({err})")


def find_key(src, stem):
    for ext in KEY_EXTS:
        p = os.path.join(src, stem + ext)
        if os.path.isfile(p):
            return p
    return None


def assemble(src, stem, extra_chain):
    crt = os.path.join(src, stem + ".crt")
    key_path = find_key(src, stem)
    if not os.path.isfile(crt) or key_path is None:
        return None
    certs = read_certs(crt)
    if cert_field(certs[-1], "subject") != cert_field(certs[-1], "issuer"):
        certs += [c for c in extra_chain if c not in certs]
    subjects = [cert_field(c, "subject") for c in certs]
    issuers = [cert_field(c, "issuer") for c in certs]
    if subjects[-1] != issuers[-1]:
        raise SetupError(
            f"{crt}: chain ends at '{subjects[-1]}' (issued by '{issuers[-1]}'), not a self-signed "
            "root; add the intermediate + Apple Root CA certs (to the .crt or chain.crt)"
        )
    for i in range(len(certs) - 1):
        if issuers[i] != subjects[i + 1]:
            raise SetupError(
                f"{crt}: cert {i} '{subjects[i]}' is issued by '{issuers[i]}', but the next cert "
                f"is '{subjects[i + 1]}' (order must be leaf -> intermediates -> root)"
            )

    key_der = read_key_der(key_path)
    leaf_pub = openssl(["x509", "-inform", "DER", "-noout", "-pubkey"], certs[0])
    key_pub = openssl(["pkey", "-inform", "DER", "-pubout"], key_der)
    if leaf_pub.strip() != key_pub.strip():
        raise SetupError(f"{key_path}: private key does not match leaf certificate in {crt}")

    with tempfile.TemporaryDirectory() as tmp:
        def pem_file(name, ders):
            p = os.path.join(tmp, name)
            with open(p, "wb") as f:
                for d in ders:
                    f.write(openssl(["x509", "-inform", "DER", "-outform", "PEM"], d))
            return p

        if len(certs) < 2:
            raise SetupError(f"{crt}: chain has only a self-signed cert; the leaf is missing")
        args = ["verify", "-no_check_time", "-x509_strict", "-CAfile", pem_file("root.pem", certs[-1:])]
        if len(certs) > 2:
            args += ["-untrusted", pem_file("mid.pem", certs[1:-1])]
        args.append(pem_file("leaf.pem", certs[:1]))
        try:
            openssl(args)
        except SetupError:
            # -x509_strict rejects some old Apple CA extensions; retry without it.
            args.remove("-x509_strict")
            openssl(args)

    root = subjects[-1]
    if "CN=Apple Root CA" not in root:
        print(f"warning: {crt}: chain root is '{root}', expected Apple Root CA", file=sys.stderr)
    print(f"  {stem}: leaf '{subjects[0]}', {len(certs)} certs -> {root}", file=sys.stderr)
    return b"".join(certs), key_der


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dest = sys.argv[1], sys.argv[2]
    if not os.path.isdir(src):
        raise SetupError(f"{src} is not a directory")

    extra_chain = []
    for name in CHAIN_NAMES:
        p = os.path.join(src, name)
        if os.path.isfile(p):
            extra_chain += read_certs(p)

    default = assemble(src, "fairplay", extra_chain)
    pairs = {}
    for slot in SLOTS:
        pair = assemble(src, slot, extra_chain) or default
        if pair is None:
            raise SetupError(
                f"no cert/key for slot {slot} and no default fairplay.crt + fairplay.key in {src}"
            )
        pairs[slot] = pair

    os.makedirs(dest, exist_ok=True)
    for slot, (chain, key) in pairs.items():
        for ext, data in ((".crt", chain), (".pem", key)):
            path = os.path.join(dest, slot + ext)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
    distinct = len({k for _, k in pairs.values()})
    print(f"wrote {len(pairs)} FairPlay slots ({distinct} distinct keys) to {dest}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SetupError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

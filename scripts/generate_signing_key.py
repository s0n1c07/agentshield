#!/usr/bin/env python3
"""
Generate an Ed25519 keypair for AgentShield AP2 mandate signing and verification.
"""

from __future__ import annotations

import json
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keypair(kid: str | None = None) -> dict[str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes_raw()

    if kid is None:
        random_suffix = secrets.token_hex(4)
        kid = f"key-{random_suffix}"

    private_hex = private_bytes.hex()
    public_hex = public_bytes.hex()

    return {
        "kid": kid,
        "private_key_hex": private_hex,
        "public_key_hex": public_hex,
    }


def main() -> None:
    pair = generate_keypair()
    kid = pair["kid"]
    priv_hex = pair["private_key_hex"]
    pub_hex = pair["public_key_hex"]

    keyring = {kid: pub_hex}
    keyring_json = json.dumps(keyring)

    print("=" * 60)
    print("AgentShield Ed25519 Mandate Signing Keypair Generated")
    print("=" * 60)
    print(f"Key ID (kid):        {kid}")
    print(f"Public Key (hex):    {pub_hex}")
    print(f"Private Key (hex):   {priv_hex}")
    print("=" * 60)
    print("Configuration for .env:")
    print(f"MANDATE_SIGNING_KID={kid}")
    print(f"MANDATE_SIGNING_PRIVATE_KEY_HEX={priv_hex}")
    print(f"MANDATE_VERIFYING_KEYRING_JSON='{keyring_json}'")
    print("=" * 60)


if __name__ == "__main__":
    main()

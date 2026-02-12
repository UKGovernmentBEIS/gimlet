"""JWT generation and validation utilities."""

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def load_or_generate_keypair(key_path: Path):
    """Load or generate RSA keypair."""
    if key_path.exists():
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    # Generate new keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Save private key
    key_path.parent.mkdir(parents=True, exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    key_path.chmod(0o600)

    # Save public key
    pub_path = key_path.with_suffix(".pub")
    with open(pub_path, "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_key


def parse_duration(s: str) -> timedelta:
    """Parse '24h', '30m', '7d' into timedelta.

    Raises:
        ValueError: If the duration string is empty, has an invalid unit,
                   or has a non-numeric value.
    """
    if not s:
        raise ValueError("Duration string cannot be empty")

    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    unit = s[-1].lower()

    if unit not in units:
        raise ValueError(
            f"Invalid duration unit '{unit}'. Valid units are: s (seconds), m (minutes), h (hours), d (days)"
        )

    value_str = s[:-1]
    if not value_str:
        raise ValueError(f"Duration must have a numeric value before the unit (e.g., '24h', not 'h')")

    try:
        value = int(value_str)
    except ValueError:
        raise ValueError(f"Invalid duration value '{value_str}'. Must be an integer.")

    if value < 0:
        raise ValueError(f"Duration value must be non-negative, got {value}")

    return timedelta(**{units[unit]: value})


def generate_agent_jwt(
    subject: str,
    service: str,
    duration: str,
    key_path: Path,
    issuer: str = "gimlet",
    scopes: list[str] | None = None,
) -> str:
    """Generate agent JWT (aud: gimlet-agent)."""
    private_key = load_or_generate_keypair(key_path)
    now = datetime.now(timezone.utc)

    claims = {
        "iss": issuer,
        "aud": "gimlet-agent",
        "sub": subject,
        "service": service,
        "iat": int(now.timestamp()),
        "exp": int((now + parse_duration(duration)).timestamp()),
        "nbf": int(now.timestamp()),
    }
    if scopes:
        claims["scope"] = scopes

    return jwt.encode(claims, private_key, algorithm="RS256")


def generate_client_jwt(
    subject: str,
    services: list[str],
    duration: str,
    key_path: Path,
    issuer: str = "gimlet",
    scopes: list[str] | None = None,
) -> str:
    """Generate client JWT (aud: gimlet-client)."""
    private_key = load_or_generate_keypair(key_path)
    now = datetime.now(timezone.utc)

    claims = {
        "iss": issuer,
        "aud": "gimlet-client",
        "sub": subject,
        "services": services,
        "iat": int(now.timestamp()),
        "exp": int((now + parse_duration(duration)).timestamp()),
        "nbf": int(now.timestamp()),
    }
    if scopes:
        claims["scope"] = scopes

    return jwt.encode(claims, private_key, algorithm="RS256")


def decode_jwt(token: str, verify: bool = False, public_key=None) -> dict:
    """Decode JWT with optional signature verification."""
    options = {"verify_signature": verify}
    if verify:
        options.update({"verify_aud": False, "verify_iss": False})
        return jwt.decode(token, public_key, algorithms=["RS256"], options=options)
    return jwt.decode(token, options=options)


def load_public_key(path: Path):
    """Load public key from PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# --- KMS Support ---


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _get_kms_client(key_arn: str):
    """Get boto3 KMS client for the key's region."""
    import boto3

    # Extract region from ARN: arn:aws:kms:REGION:account:key/key-id
    parts = key_arn.split(":")
    if len(parts) >= 4:
        region = parts[3]
    else:
        region = None

    return boto3.client("kms", region_name=region)


def get_kms_public_key(key_arn: str) -> bytes:
    """Get public key from KMS in PEM format."""
    client = _get_kms_client(key_arn)
    response = client.get_public_key(KeyId=key_arn)

    # Response contains DER-encoded public key, convert to PEM
    public_key_der = response["PublicKey"]
    public_key = serialization.load_der_public_key(public_key_der)

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _sign_with_kms(key_arn: str, message: bytes) -> bytes:
    """Sign a message using KMS with RS256 (RSASSA_PKCS1_V1_5_SHA_256).

    Raises:
        RuntimeError: If KMS returns an unexpected response format.
    """
    client = _get_kms_client(key_arn)

    # Hash the message (KMS expects a digest for DIGEST message type)
    digest = hashlib.sha256(message).digest()

    response = client.sign(
        KeyId=key_arn,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )

    if "Signature" not in response:
        raise RuntimeError(
            f"KMS sign response missing 'Signature' field. Response keys: {list(response.keys())}"
        )

    return response["Signature"]


def _build_jwt_with_kms(claims: dict, key_arn: str) -> str:
    """Build and sign a JWT using KMS."""
    # Build header
    header = {"alg": "RS256", "typ": "JWT"}
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())

    # Build payload
    payload_b64 = _base64url_encode(json.dumps(claims, separators=(",", ":")).encode())

    # Create signing input
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # Sign with KMS
    signature = _sign_with_kms(key_arn, signing_input)
    signature_b64 = _base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def generate_agent_jwt_kms(
    subject: str,
    service: str,
    duration: str,
    key_arn: str,
    issuer: str = "gimlet",
    scopes: list[str] | None = None,
) -> str:
    """Generate agent JWT using KMS for signing (aud: gimlet-agent)."""
    now = datetime.now(timezone.utc)

    claims = {
        "iss": issuer,
        "aud": "gimlet-agent",
        "sub": subject,
        "service": service,
        "iat": int(now.timestamp()),
        "exp": int((now + parse_duration(duration)).timestamp()),
        "nbf": int(now.timestamp()),
    }
    if scopes:
        claims["scope"] = scopes

    return _build_jwt_with_kms(claims, key_arn)


def generate_client_jwt_kms(
    subject: str,
    services: list[str],
    duration: str,
    key_arn: str,
    issuer: str = "gimlet",
    scopes: list[str] | None = None,
) -> str:
    """Generate client JWT using KMS for signing (aud: gimlet-client)."""
    now = datetime.now(timezone.utc)

    claims = {
        "iss": issuer,
        "aud": "gimlet-client",
        "sub": subject,
        "services": services,
        "iat": int(now.timestamp()),
        "exp": int((now + parse_duration(duration)).timestamp()),
        "nbf": int(now.timestamp()),
    }
    if scopes:
        claims["scope"] = scopes

    return _build_jwt_with_kms(claims, key_arn)

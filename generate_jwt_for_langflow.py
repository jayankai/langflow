#!/usr/bin/env python3
"""Generate a JWT for Langflow iframe authentication (no external dependencies)."""

import base64
import hashlib
import hmac
import json
import time

# Constants
BASE64_PADDING = 4


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url format without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def create_jwt_header() -> str:
    """Create JWT header in base64url format."""
    header = {"alg": "HS256", "typ": "JWT"}
    return base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))


def create_jwt_payload(email: str, expiration_hours: int = 24) -> str:
    """Create JWT payload with email and expiration."""
    now = int(time.time())
    payload = {
        "email": email,
        "iat": now,
        "exp": now + (expiration_hours * 3600),
    }
    return base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def create_jwt_signature(header: str, payload: str, secret: str) -> str:
    """Create JWT signature using HMAC-SHA256."""
    message = f"{header}.{payload}".encode()
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    return base64url_encode(signature)


def create_langflow_jwt(email: str, secret: str, expiration_hours: int = 24) -> str:
    """Create a complete JWT token for Langflow iframe authentication."""
    header = create_jwt_header()
    payload = create_jwt_payload(email, expiration_hours)
    signature = create_jwt_signature(header, payload, secret)
    return f"{header}.{payload}.{signature}"


def format_timestamp(timestamp: int) -> str:
    """Format timestamp as human-readable string."""
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(timestamp))


def main():
    """Main function to generate and display JWT token."""
    # Use environment variable or default secret
    secret = "MJVZhZaWGjEz4cvHDo0ktjms5d74aEJW9Ks2R9nV59fBPaeZ50xyh1r1yVcM3U5YLkkiAxR68fGnFjtj7DeWpRiYRKqkuyUVwRAz"  # noqa: S105
    email = "jayanka@aisel.co"
    expiration_hours = 24

    token = create_langflow_jwt(email, secret, expiration_hours)
    print(f"Generated link: http://localhost:7860/login?token={token}")  # noqa: T201

    return token


if __name__ == "__main__":
    main()

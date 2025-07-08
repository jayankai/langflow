"""Generate a test JWT token for iframe authentication testing."""

import os
import sys
import time

import jwt

# Constants
SECRET_PREVIEW_LENGTH = 10
MIN_ARGS_FOR_EMAIL = 1
MIN_ARGS_FOR_SECRET = 2


def generate_test_token(email: str = "test@example.com", secret: str | None = None) -> str:
    """Generate a JWT token with email claim for testing."""
    if not secret:
        # Try to get secret from environment variable
        secret = os.getenv("LANGFLOW_AUTHENTICATION_PROXY_SECRET", "test-secret")
        secret_preview = f"{secret[:SECRET_PREVIEW_LENGTH]}..." if len(secret) > SECRET_PREVIEW_LENGTH else secret
        print(f"Using secret: {secret_preview}")  # noqa: T201

    current_time = int(time.time())
    payload = {
        "email": email,
        "sub": "123",
        "iat": current_time,
        "exp": current_time + 3600,  # Expires in 1 hour
    }
    return jwt.encode(payload, secret, algorithm="HS256")


if __name__ == "__main__":
    # Default values
    email = "test@example.com"
    secret = None  # Will use environment variable or default

    # Allow command line arguments
    if len(sys.argv) > MIN_ARGS_FOR_EMAIL:
        email = sys.argv[1]
    if len(sys.argv) > MIN_ARGS_FOR_SECRET:
        secret = sys.argv[2]

    token = generate_test_token(email, secret)
    print(f"Generated JWT token for email: {email}")  # noqa: T201
    print(f"Token: {token}")  # noqa: T201
    print()  # noqa: T201
    print("To test with curl:")  # noqa: T201
    print(f"curl -H 'X-Iframe-Token: {token}' http://localhost:7860/health")  # noqa: T201
    print()  # noqa: T201
    print("To use in iframe URL:")  # noqa: T201
    print(f"http://localhost:3000?token={token}")  # noqa: T201

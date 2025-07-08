"""Iframe authentication endpoint for Langflow."""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from langflow.api.v1.schemas import Token
from langflow.initial_setup.setup import get_or_create_default_folder
from langflow.services.auth.utils import create_user_longterm_token
from langflow.services.database.models.user.crud import get_user_by_id
from langflow.services.deps import get_session, get_settings_service, get_variable_service

router = APIRouter(tags=["iframe_auth"])

# Constants
JWT_PARTS_COUNT = 3
BASE64_PADDING = 4


@router.post("/auto_login_with_token", response_model=Token)
async def auto_login_with_token(
    request: Request, response: Response, db: Annotated[AsyncSession, Depends(get_session)]
) -> dict[str, Any]:
    """Authenticate user via JWT token from iframe request."""
    logger = logging.getLogger(__name__)

    # Extract token from request body
    try:
        body = await request.json()
        iframe_token = body.get("token")
        logger.info("Token extracted from request body: %s...", iframe_token[:20] if iframe_token else "None")
    except Exception as e:
        logger.exception("Failed to parse request body")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request body. Expected JSON with 'token' field.",
        ) from e

    if not iframe_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is required",
        )

    # Get secret from environment
    secret = os.getenv("LANGFLOW_AUTHENTICATION_PROXY_SECRET")
    if not secret:
        logger.error("LANGFLOW_AUTHENTICATION_PROXY_SECRET not configured")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication proxy not configured",
        )

    # Validate JWT token
    try:
        # Manual JWT decoding without external library validation
        parts = iframe_token.split(".")
        if len(parts) != JWT_PARTS_COUNT:
            invalid_format_msg = "Invalid JWT format"
            raise ValueError(invalid_format_msg)

        # Decode payload
        payload_b64 = parts[1]
        # Add padding if needed
        padding = BASE64_PADDING - len(payload_b64) % BASE64_PADDING
        if padding != BASE64_PADDING:
            payload_b64 += "=" * padding
        payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
        payload = json.loads(payload_json)

        # Verify expiration
        current_time = int(time.time())
        if payload.get("exp", 0) < current_time:
            msg = "Token expired"
            raise ValueError(msg)

        # Verify signature
        expected_signature = hmac.new(
            secret.encode("utf-8"),
            f"{parts[0]}.{parts[1]}".encode(),
            hashlib.sha256,
        ).digest()
        expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).decode("utf-8").rstrip("=")

        if parts[2] != expected_signature_b64:
            invalid_signature_msg = "Invalid signature"
            raise ValueError(invalid_signature_msg)

        email = payload.get("email")
        if not email:
            msg = "Email not found in token"
            raise ValueError(msg)

    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.exception("JWT validation failed")
        logger.exception("Token: %s...", iframe_token[:50])  # Log first 50 chars of token
        logger.exception("Secret configured: %s", bool(secret))

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {e}",
        ) from e

    # Check if email is in system managers list
    managers_str = os.getenv("SYSTEM_MANAGERS", "")
    system_managers = [email.strip() for email in managers_str.split(",") if email.strip()]
    logger.info("Email from token: %s", email)
    logger.info("System managers: %s", system_managers)

    if email not in system_managers:
        logger.error("Email %s not in system managers list: %s", email, system_managers)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Email {email} not authorized for iframe authentication",
        )

    # Get or create super user using the same approach as auto_login
    auth_settings = get_settings_service().auth_settings

    try:
        # Use create_user_longterm_token which handles user creation internally
        user_id, tokens = await create_user_longterm_token(db)

        # Set cookies like in auto_login
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Set to None to make it a session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )

        user = await get_user_by_id(db, user_id)

        if user:
            if user.store_api_key is None:
                user.store_api_key = ""

            response.set_cookie(
                "apikey_tkn_lflw",
                str(user.store_api_key),  # Ensure it's a string
                httponly=auth_settings.ACCESS_HTTPONLY,
                samesite=auth_settings.ACCESS_SAME_SITE,
                secure=auth_settings.ACCESS_SECURE,
                expires=None,  # Set to None to make it a session cookie
                domain=auth_settings.COOKIE_DOMAIN,
            )

        # Initialize user variables and create default folder like in login
        await get_variable_service().initialize_user_variables(user_id, db)
        _ = await get_or_create_default_folder(db, user_id)

        logger.info("Successfully authenticated user %s via iframe token", email)
        if tokens.get("refresh_token") is None:
            tokens["refresh_token"] = ""

    except Exception as e:
        logger.exception("Failed to create user or tokens")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create authentication: {e}",
        ) from e

    return tokens

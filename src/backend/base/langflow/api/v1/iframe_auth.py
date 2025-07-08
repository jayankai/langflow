"""Iframe authentication endpoint for Langflow."""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from langflow.api.v1.schemas import Token
from langflow.initial_setup.setup import get_or_create_default_folder
from langflow.services.auth.utils import create_user_longterm_token, create_user_tokens, get_password_hash
from langflow.services.database.models.user.crud import get_user_by_id, get_user_by_username
from langflow.services.database.models.user.model import User
from langflow.services.deps import get_session, get_settings_service, get_variable_service

router = APIRouter(tags=["iframe_auth"])

# Constants
JWT_PARTS_COUNT = 3
BASE64_PADDING = 4
DEFAULT_PASSWORD_LENGTH = 32


def generate_secure_password() -> str:
    """Generate a secure random password for iframe users."""
    return str(uuid.uuid4()).replace("-", "")[:DEFAULT_PASSWORD_LENGTH]


def validate_email_format(email: str) -> bool:
    """Basic email format validation."""
    if not email or not isinstance(email, str):
        return False
    return "@" in email and "." in email.split("@")[1]


def validate_username_format(username: str) -> bool:
    """Basic username format validation."""
    if not username or not isinstance(username, str):
        return False
    # Username should be alphanumeric with some special characters allowed
    import re

    return bool(re.match(r"^[a-zA-Z0-9._-]+$", username))


async def get_or_create_user_by_email(email: str, db: AsyncSession) -> tuple[Any, dict]:
    """Get existing user by email (username) or create new user if doesn't exist."""
    logger = logging.getLogger(__name__)

    try:
        # Validate email format
        if not validate_email_format(email):
            logger.error("Invalid email format: %s", email)
            error_msg = f"Invalid email format: {email}"
            raise ValueError(error_msg)

        # Try to get existing user by email as username
        user = await get_user_by_username(db, email)

        if user:
            logger.info("Found existing user with email %s", email)
            try:
                # Create tokens for existing user
                tokens = await create_user_tokens(user.id, db, update_last_login=True)
            except Exception as e:
                logger.exception("Failed to create tokens for existing user %s", email)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create tokens for user: {e!s}"
                ) from e
            else:
                return user.id, tokens
        else:
            logger.info("Creating new user with email %s", email)
            try:
                # Create new user with email as username
                secure_password = generate_secure_password()
                new_user = User(
                    username=email,
                    password=get_password_hash(secure_password),
                    is_active=True,
                    is_superuser=False,
                    last_login_at=None,
                )

                db.add(new_user)
                await db.commit()
                await db.refresh(new_user)

                # Create tokens for new user
                tokens = await create_user_tokens(new_user.id, db, update_last_login=True)
                logger.info("Successfully created new user with email %s", email)
            except IntegrityError as e:
                await db.rollback()
                logger.exception("Database integrity error creating user with email %s", email)
                # User might have been created by another request, try to get it
                try:
                    user = await get_user_by_username(db, email)
                    if user:
                        tokens = await create_user_tokens(user.id, db, update_last_login=True)
                        return user.id, tokens
                except Exception as retry_e:
                    logger.exception("Failed to get user after integrity error")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create or retrieve user"
                    ) from retry_e
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create user due to database constraint",
                ) from e
            except SQLAlchemyError as e:
                await db.rollback()
                logger.exception("Database error creating user with email %s", email)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database error occurred while creating user",
                ) from e
            except Exception as e:
                await db.rollback()
                logger.exception("Unexpected error creating user with email %s", email)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create user: {e!s}"
                ) from e
            else:
                return new_user.id, tokens

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in get_or_create_user_by_email")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during user creation"
        ) from e


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
    except json.JSONDecodeError as e:
        logger.exception("Failed to parse JSON request body")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON in request body",
        ) from e
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

    if not isinstance(iframe_token, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token must be a string",
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

        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload_json = payload_bytes.decode("utf-8")
            payload = json.loads(payload_json)
        except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as e:
            logger.exception("Failed to decode JWT payload")
            error_msg = "Invalid JWT payload encoding"
            raise ValueError(error_msg) from e

        # Verify expiration
        current_time = int(time.time())
        exp_time = payload.get("exp", 0)
        if not isinstance(exp_time, int | float) or exp_time < current_time:
            msg = "Token expired"
            raise ValueError(msg)

        # Verify signature
        try:
            expected_signature = hmac.new(
                secret.encode("utf-8"),
                f"{parts[0]}.{parts[1]}".encode(),
                hashlib.sha256,
            ).digest()
            expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).decode("utf-8").rstrip("=")

            if parts[2] != expected_signature_b64:
                invalid_signature_msg = "Invalid signature"
                raise ValueError(invalid_signature_msg)
        except Exception as e:
            logger.exception("Failed to verify JWT signature")
            error_msg = "Invalid JWT signature"
            raise ValueError(error_msg) from e

        email = payload.get("email")
        username = payload.get("username")  # Extract username from payload

        if not email:
            msg = "Email not found in token"
            raise ValueError(msg)

        if not validate_email_format(email):
            msg = "Invalid email format in token"
            raise ValueError(msg)

        if username and not validate_username_format(username):
            logger.warning("Invalid username format in token: %s", username)
            username = None  # Reset to None if invalid

    except ValueError as e:
        logger.exception("JWT validation failed")
        logger.debug("Token: %s...", iframe_token[:50])  # Log first 50 chars of token
        logger.debug("Secret configured: %s", bool(secret))

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {e}",
        ) from e
    except Exception as e:
        logger.exception("Unexpected error during JWT validation")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed",
        ) from e

    # Check if email is in system managers list
    managers_str = os.getenv("SYSTEM_MANAGERS", "")
    system_managers = [email.strip() for email in managers_str.split(",") if email.strip()]
    logger.info("Email from token: %s", email)
    logger.info("Username from token: %s", username)
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
        # Determine which user to authenticate based on username and email
        if username:
            try:
                # Check if username is a superuser
                super_user = await get_user_by_username(db, username)
                if super_user and super_user.is_superuser:
                    logger.info("Username %s is a superuser, creating longterm token", username)
                    user_id, tokens = await create_user_longterm_token(db)
                elif username == email:
                    # Username is email, get or create user by email
                    logger.info("Username %s is email, getting/creating user by email", username)
                    user_id, tokens = await get_or_create_user_by_email(email, db)
                else:
                    # Username is different from email, check if it exists
                    user = await get_user_by_username(db, username)
                    if user:
                        logger.info("Username %s exists, creating tokens", username)
                        tokens = await create_user_tokens(user.id, db, update_last_login=True)
                        user_id = user.id
                    else:
                        # Username doesn't exist, fall back to email
                        logger.info("Username %s doesn't exist, falling back to email", username)
                        user_id, tokens = await get_or_create_user_by_email(email, db)
            except Exception:
                logger.exception("Error processing username %s, falling back to email", username)
                # Fallback to email if username processing fails
                user_id, tokens = await get_or_create_user_by_email(email, db)
        else:
            # No username in payload, use email
            logger.info("No username in payload, using email %s", email)
            user_id, tokens = await get_or_create_user_by_email(email, db)

        # Validate tokens were created successfully
        if not tokens or not isinstance(tokens, dict):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create authentication tokens"
            )

        if "access_token" not in tokens:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Access token not generated")

        # Set cookies like in auto_login
        try:
            response.set_cookie(
                "access_token_lf",
                tokens["access_token"],
                httponly=auth_settings.ACCESS_HTTPONLY,
                samesite=auth_settings.ACCESS_SAME_SITE,
                secure=auth_settings.ACCESS_SECURE,
                expires=None,  # Set to None to make it a session cookie
                domain=auth_settings.COOKIE_DOMAIN,
            )
        except Exception:
            logger.exception("Failed to set access token cookie")
            # Continue without cookie if it fails

        try:
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
        except Exception:
            logger.exception("Failed to set API key cookie")
            # Continue without API key cookie if it fails

        # Initialize user variables and create default folder like in login
        try:
            await get_variable_service().initialize_user_variables(user_id, db)
            _ = await get_or_create_default_folder(db, user_id)
        except Exception:
            logger.exception("Failed to initialize user variables or create default folder")
            # Continue even if initialization fails

        logger.info("Successfully authenticated user %s via iframe token", email)
        if tokens.get("refresh_token") is None:
            tokens["refresh_token"] = ""

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to create user or tokens")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create authentication: {e!s}",
        ) from e

    return tokens

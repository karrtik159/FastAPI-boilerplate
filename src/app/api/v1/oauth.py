"""OAuth Login/Register Endpoints.

This module handles OAuth authentication flow where:
1. Frontend authenticates user via Firebase (Google/Apple OAuth)
2. Frontend sends provider ID and user info to this endpoint
3. Backend looks up or creates the user
4. Backend returns JWT tokens for subsequent API calls

TODO: SECURITY ENHANCEMENT - Firebase Token Verification
======================================================
Currently, this endpoint trusts the provider_id sent by the frontend.
For production, you should verify the Firebase ID token to ensure authenticity.

Steps to implement:
1. Add `google-auth` to requirements.txt
2. Install Firebase Admin SDK: `pip install firebase-admin`
3. Initialize Firebase Admin with your service account
4. Verify the token before trusting provider_id:

    from firebase_admin import auth

    async def verify_firebase_token(token: str) -> dict:
        try:
            decoded_token = auth.verify_id_token(token)
            return {
                "uid": decoded_token["uid"],
                "email": decoded_token.get("email"),
                "name": decoded_token.get("name"),
                "picture": decoded_token.get("picture"),
                "provider": decoded_token.get("firebase", {}).get("sign_in_provider"),
            }
        except Exception as e:
            raise UnauthorizedException("Invalid Firebase token")

See: https://firebase.google.com/docs/auth/admin/verify-id-tokens
"""

import re
import secrets
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.config import settings
from ...core.db.database import async_get_db
from ...core.exceptions.http_exceptions import BadRequestException, NotFoundException
from ...core.schemas import Token
from ...core.security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    create_refresh_token,
)
from ...crud.crud_users import crud_users
from ...schemas.user import OAuthLogin, UserCreateInternal, UserRead

router = APIRouter(tags=["oauth"])


def _generate_username_from_email(email: str) -> str:
    """Generate a username from email address.

    Takes the part before @ and makes it lowercase alphanumeric. Adds random suffix to ensure uniqueness.
    """
    prefix = email.split("@")[0].lower()
    # Remove non-alphanumeric characters
    prefix = re.sub(r"[^a-z0-9]", "", prefix)
    # Truncate if too long (max 20 chars, leave room for suffix)
    prefix = prefix[:14]
    # Add random suffix for uniqueness
    suffix = secrets.token_hex(3)  # 6 chars
    return f"{prefix}{suffix}"


@router.post("/oauth/login", response_model=Token)
async def oauth_login(
    response: Response,
    oauth_data: OAuthLogin,
    db: Annotated[AsyncSession, Depends(async_get_db)],
) -> dict[str, str]:
    """OAuth login/register endpoint.

    This endpoint handles both login and registration for OAuth users:

    1. Receives provider info (google/apple) and provider_id from frontend
    2. Checks if a user with this provider_id already exists
    3. If exists: logs in the user (returns JWT tokens)
    4. If not exists: creates a new user and logs them in

    The frontend is responsible for:
    - Authenticating with Firebase (Google/Apple Sign-In)
    - Getting the user's provider_id (uid), email, name, and profile picture
    - Sending this information to this endpoint

    Args:
        oauth_data: OAuth login data containing provider, provider_id, email, etc.
        db: Database session

    Returns:
        JWT access token and token type

    Note:
        TODO: In production, verify Firebase ID token before trusting provider_id.
        See module docstring for implementation details.
    """
    provider = oauth_data.provider
    provider_id = oauth_data.provider_id

    # Determine which field to search by
    if provider == "google":
        lookup_field = "google_id"
    elif provider == "apple":
        lookup_field = "apple_id"
    else:
        raise BadRequestException(f"Unsupported OAuth provider: {provider}")

    # Check if user already exists with this OAuth ID
    existing_user = await crud_users.get(
        db=db, schema_to_select=UserRead, is_deleted=False, **{lookup_field: provider_id}
    )

    if existing_user:
        # User exists - log them in
        user = existing_user
    else:
        # Check if email is already registered (could be email/password user)
        email_user = await crud_users.get(
            db=db,
            email=oauth_data.email,
            is_deleted=False,
        )

        if email_user:
            # Email exists but with different auth method
            # Option 1: Link accounts (update existing user with OAuth ID)
            # Option 2: Reject and ask user to login with original method
            # For now, we'll link the accounts by updating the OAuth ID
            await crud_users.update(
                db=db,
                object={lookup_field: provider_id},
                email=oauth_data.email,
            )
            user = await crud_users.get(
                db=db,
                email=oauth_data.email,
                schema_to_select=UserRead,
            )
        else:
            # New user - register them
            username = _generate_username_from_email(oauth_data.email)

            # Ensure username is unique (edge case handling)
            while await crud_users.exists(db=db, username=username):
                username = _generate_username_from_email(oauth_data.email)

            # Prepare user data
            user_data: dict[str, Any] = {
                "name": oauth_data.name or oauth_data.email.split("@")[0][:30],
                "username": username,
                "email": oauth_data.email,
                "auth_provider": provider,
                "hashed_password": None,  # OAuth users don't have passwords
            }

            # Set the provider-specific ID
            if provider == "google":
                user_data["google_id"] = provider_id
            else:
                user_data["apple_id"] = provider_id

            # Add profile image if provided
            if oauth_data.profile_image_url:
                user_data["profile_image_url"] = oauth_data.profile_image_url

            # Create the user
            user_internal = UserCreateInternal(**user_data)
            user = await crud_users.create(db=db, object=user_internal, schema_to_select=UserRead)

            if user is None:
                raise NotFoundException("Failed to create user")

    # Generate JWT tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(data={"sub": user["username"]}, expires_delta=access_token_expires)

    refresh_token = await create_refresh_token(data={"sub": user["username"]})
    max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=max_age,
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/oauth/check/{provider}/{provider_id}")
async def check_oauth_user(
    provider: str,
    provider_id: str,
    db: Annotated[AsyncSession, Depends(async_get_db)],
) -> dict[str, Any]:
    """Check if an OAuth user is already registered.

    This endpoint allows the frontend to check if a user with the given
    OAuth provider ID already exists before attempting to register.

    Args:
        provider: OAuth provider name ("google" or "apple")
        provider_id: Unique user ID from the OAuth provider

    Returns:
        Dictionary with:
        - is_registered: bool - whether user exists
        - username: str | None - username if registered
    """
    if provider not in ("google", "apple"):
        raise BadRequestException(f"Unsupported OAuth provider: {provider}")

    lookup_field = "google_id" if provider == "google" else "apple_id"

    existing_user = await crud_users.get(
        db=db, schema_to_select=UserRead, is_deleted=False, **{lookup_field: provider_id}
    )

    if existing_user:
        return {
            "is_registered": True,
            "username": existing_user["username"],
        }

    return {
        "is_registered": False,
        "username": None,
    }

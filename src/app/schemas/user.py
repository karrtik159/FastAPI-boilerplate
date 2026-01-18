from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from ..core.schemas import PersistentDeletion, TimestampSchema, UUIDSchema


class AuthProvider(str, Enum):
    """Enum for authentication providers."""

    EMAIL = "email"
    GOOGLE = "google"
    APPLE = "apple"


class UserBase(BaseModel):
    name: Annotated[str, Field(min_length=2, max_length=30, examples=["User Userson"])]
    username: Annotated[str, Field(min_length=2, max_length=20, pattern=r"^[a-z0-9]+$", examples=["userson"])]
    email: Annotated[EmailStr, Field(examples=["user.userson@example.com"])]


class User(TimestampSchema, UserBase, UUIDSchema, PersistentDeletion):
    profile_image_url: Annotated[str, Field(default="https://www.profileimageurl.com")]
    hashed_password: str | None = None
    is_superuser: bool = False
    tier_id: int | None = None
    google_id: str | None = None
    apple_id: str | None = None
    auth_provider: str = "email"


class UserRead(BaseModel):
    id: int

    name: Annotated[str, Field(min_length=2, max_length=30, examples=["User Userson"])]
    username: Annotated[str, Field(min_length=2, max_length=20, pattern=r"^[a-z0-9]+$", examples=["userson"])]
    email: Annotated[EmailStr, Field(examples=["user.userson@example.com"])]
    profile_image_url: str
    tier_id: int | None
    auth_provider: str = "email"


class UserCreate(UserBase):
    model_config = ConfigDict(extra="forbid")

    password: Annotated[str, Field(pattern=r"^.{8,}|[0-9]+|[A-Z]+|[a-z]+|[^a-zA-Z0-9]+$", examples=["Str1ngst!"])]


class UserCreateInternal(UserBase):
    hashed_password: str | None = None
    google_id: str | None = None
    apple_id: str | None = None
    auth_provider: str = "email"
    profile_image_url: str = "https://profileimageurl.com"


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str | None, Field(min_length=2, max_length=30, examples=["User Userberg"], default=None)]
    username: Annotated[
        str | None, Field(min_length=2, max_length=20, pattern=r"^[a-z0-9]+$", examples=["userberg"], default=None)
    ]
    email: Annotated[EmailStr | None, Field(examples=["user.userberg@example.com"], default=None)]
    profile_image_url: Annotated[
        str | None,
        Field(
            pattern=r"^(https?|ftp)://[^\s/$.?#].[^\s]*$", examples=["https://www.profileimageurl.com"], default=None
        ),
    ]


class UserUpdateInternal(UserUpdate):
    updated_at: datetime


class UserTierUpdate(BaseModel):
    tier_id: int


class UserDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_deleted: bool
    deleted_at: datetime


class UserRestoreDeleted(BaseModel):
    is_deleted: bool


# ============================================================================
# OAuth Schemas
# ============================================================================


class OAuthLogin(BaseModel):
    """Schema for OAuth login/register request.

    The frontend handles authentication via Firebase and passes the provider ID
    (google_id or apple_id) along with user information.

    TODO: In production, add Firebase token verification to ensure the provider_id
    is authentic. Currently trusting the frontend for development simplicity.
    See: https://firebase.google.com/docs/auth/admin/verify-id-tokens
    """

    model_config = ConfigDict(extra="forbid")

    provider: Literal["google", "apple"] = Field(description="OAuth provider name")
    provider_id: Annotated[str, Field(min_length=1, description="Unique user ID from the OAuth provider")]
    email: Annotated[EmailStr, Field(description="User's email from OAuth provider")]
    name: Annotated[str | None, Field(max_length=30, default=None, description="User's display name from OAuth")]
    profile_image_url: Annotated[str | None, Field(default=None, description="Profile image URL from OAuth provider")]


class OAuthUserRead(UserRead):
    """Extended user read schema with OAuth-specific fields."""

    google_id: str | None = None
    apple_id: str | None = None

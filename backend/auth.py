from typing import Optional
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
import logging

from models import User, Organization
from security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    verify_token,
    TokenData,
    Token,
)

logger = logging.getLogger(__name__)


class UserRegister(BaseModel):
    email: EmailStr
    password: str
    organization_name: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str
    organization_id: int


def register_user(user_data: UserRegister, db: Session) -> dict:
    """Register a new user and create organization if it doesn't exist."""
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Find or create organization
    org = db.query(Organization).filter(
        Organization.name == user_data.organization_name
    ).first()

    if not org:
        org = Organization(name=user_data.organization_name)
        db.add(org)
        db.flush()  # Get the org ID
        logger.info(f"Created organization: {user_data.organization_name}")

    # Create user
    hashed_password = get_password_hash(user_data.password)
    user = User(
        email=user_data.email,
        hashed_password=hashed_password,
        organization_id=org.id,
        role="ADMIN" if db.query(User).filter(User.organization_id == org.id).count() == 0 else "ANALYST"
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(f"User registered: {user_data.email} in org {org.name}")

    # Create tokens
    token_data = {
        "email": user.email,
        "user_id": user.id,
        "organization_id": user.organization_id,
        "role": user.role
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return {
        "user": UserOut.from_orm(user),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


def login_user(user_data: UserLogin, db: Session) -> dict:
    """Authenticate user and return tokens."""
    user = db.query(User).filter(User.email == user_data.email).first()

    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    logger.info(f"User logged in: {user_data.email}")

    # Create tokens
    token_data = {
        "email": user.email,
        "user_id": user.id,
        "organization_id": user.organization_id,
        "role": user.role
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return {
        "user": UserOut.from_orm(user),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


def verify_user_token(token: str, db: Session) -> TokenData:
    """Verify token and return user data."""
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    user = db.query(User).filter(User.id == token_data.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return token_data

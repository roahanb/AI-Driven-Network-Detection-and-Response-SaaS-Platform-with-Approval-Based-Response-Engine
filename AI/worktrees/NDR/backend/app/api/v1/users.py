from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.database import get_db
from app.models.user import User, UserRole
from app.models.audit import AuditLog
from app.schemas.user import UserOut, UserUpdateRequest, UserRoleUpdateRequest
from app.schemas.auth import InviteUserRequest
from app.core.dependencies import get_current_user, require_admin
from app.core.security import hash_password
import secrets
import string

router = APIRouter(prefix="/users", tags=["Users"])


def _generate_temp_password(length=12) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    return "".join(secrets.choice(alphabet) for _ in range(length))


@router.get("", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(
        select(User).where(User.organization_id == current_user.organization_id)
    )
    return result.scalars().all()


@router.post("/invite", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def invite_user(
    payload: InviteUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Count org users
    result = await db.execute(
        select(User).where(User.organization_id == current_user.organization_id)
    )
    from app.models.user import Organization
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = org_result.scalar_one()
    existing_count = len(result.scalars().all())
    if existing_count >= org.max_users:
        raise HTTPException(status_code=400, detail="Organization user limit reached")

    temp_password = _generate_temp_password()
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(temp_password),
        role=UserRole(payload.role),
        organization_id=current_user.organization_id,
        is_verified=False,
    )
    db.add(user)
    await db.flush()

    db.add(AuditLog(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        action="invite_user",
        details={"invited_email": payload.email, "role": payload.role},
    ))

    # In production, send invite email with temp_password
    # await send_invite_email(payload.email, temp_password)

    return user


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(
        select(User).where(and_(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        ))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Users can update themselves; admins can update anyone in org
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(User).where(and_(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        ))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.notification_email is not None:
        user.notification_email = payload.notification_email
    if payload.notification_slack is not None:
        user.notification_slack = payload.notification_slack

    return user


@router.patch("/{user_id}/role", response_model=UserOut)
async def update_user_role(
    user_id: int,
    payload: UserRoleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    result = await db.execute(
        select(User).where(and_(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        ))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        user.role = UserRole(payload.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {payload.role}")

    db.add(AuditLog(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        action="update_role",
        details={"target_user": user_id, "new_role": payload.role},
    ))

    return user


@router.delete("/{user_id}")
async def deactivate_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    result = await db.execute(
        select(User).where(and_(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        ))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    return {"message": "User deactivated"}

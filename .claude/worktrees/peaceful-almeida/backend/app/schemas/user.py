from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    organization_id: int
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    notification_email: bool
    notification_slack: bool
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class OrganizationOut(BaseModel):
    id: int
    name: str
    slug: str
    is_active: bool
    max_users: int
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    notification_email: Optional[bool] = None
    notification_slack: Optional[bool] = None


class UserRoleUpdateRequest(BaseModel):
    role: str

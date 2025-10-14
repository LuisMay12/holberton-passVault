from dataclasses import dataclass
from typing import Optional, TypedDict, List, Dict


@dataclass
class RegisterCredentialBody:
    """Schema for /vault/register body."""
    app_name: str
    password: str
    master_password: str
    app_login_url: Optional[str] = None


@dataclass
class DetailRequestBody:
    """Schema for /vault/detail body."""
    master_password: str


class AppItem(TypedDict):
    name: str
    id: str


class VaultListResponse(TypedDict):
    apps: List[AppItem]

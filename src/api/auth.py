"""
CyberSentinel AI — JWT Authentication
Production-ready JWT creation, validation, and RBAC dependency injection.
Passwords are hashed with bcrypt. Tokens expire after JWT_EXPIRE_MINUTES.
"""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from src.core.config import api as api_cfg
from src.core.constants import UserRole

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt (work factor 12)."""
    return pwd_context.hash(password)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a signed JWT access token.
    Includes 'sub' (username), 'role', and 'exp' (expiry timestamp).
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=api_cfg.jwt_expiry_minutes)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, api_cfg.jwt_secret, algorithm=api_cfg.jwt_algorithm)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT. Raises HTTP 401 on invalid or expired tokens.
    """
    try:
        return jwt.decode(
            token, api_cfg.jwt_secret, algorithms=[api_cfg.jwt_algorithm]
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    FastAPI dependency — extracts and validates the current user from the Bearer token.
    Inject with: user: dict = Depends(get_current_user)
    """
    payload = decode_token(token)
    username: Optional[str] = payload.get("sub")
    role:     Optional[str] = payload.get("role", UserRole.VIEWER)

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
        )
    return {"username": username, "role": role}


def require_role(*allowed_roles: str):
    """
    FastAPI dependency factory — restricts an endpoint to specific user roles.

    Usage:
        @app.delete("/api/v1/incidents/{id}")
        async def delete_incident(user = Depends(require_role("admin"))):
            ...
    """
    async def _check_role(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user['role']}' is not authorised for this action. "
                       f"Required: {', '.join(allowed_roles)}",
            )
        return user
    return _check_role

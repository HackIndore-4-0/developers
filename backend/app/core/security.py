from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _create_token(subject: str, token_type: str, expires_delta: timedelta, org_id: str | None = None, roles: list[str] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    if org_id:
        payload["org_id"] = org_id
    if roles:
        payload["roles"] = roles
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(subject: str, org_id: str | None = None, roles: list[str] | None = None) -> str:
    return _create_token(subject, "access", timedelta(minutes=settings.access_token_expire_minutes), org_id, roles)


def create_refresh_token(subject: str, org_id: str | None = None, roles: list[str] | None = None) -> str:
    return _create_token(subject, "refresh", timedelta(days=settings.refresh_token_expire_days), org_id, roles)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None
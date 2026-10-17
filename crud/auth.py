from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from sqlalchemy.orm import Session
from models.user import User
from schemas.user import UserCreate
from config import settings

_PASSWORD_ALGORITHM = "pbkdf2_sha256"
_PASSWORD_ITERATIONS = 600_000
_TOKEN_ALGORITHM = "HS256"
_TOKEN_VERSION = "v1"
_ACCESS_TOKEN_EXPIRE_MINUTES = 15
_REFRESH_TOKEN_EXPIRE_DAYS = 30
_REVOKED_TOKEN_IDS: set[str] = set()


def _secret_key() -> bytes:
  
    secret = settings.secret_key

    if not secret or len(secret) < 32:
        raise RuntimeError(
            "SECRET_KEY must contain at least 32 characters"
        )

    return secret.encode("utf-8")

def _encode_part(value: Any) -> str:
   
    data = json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    return (
        base64.urlsafe_b64encode(data)
        .rstrip(b"=")
        .decode("ascii")
    )


def _decode_part(value: str) -> Any:
    """
    Decode a URL-safe Base64 string.
    """
    padded = value + "=" * (-len(value) % 4)

    return json.loads(
        base64.urlsafe_b64decode(padded).decode("utf-8")
    )


def _encode_bytes(value: bytes) -> str:
    """
    URL-safe Base64 encoding without padding.
    """
    return (
        base64.urlsafe_b64encode(value)
        .rstrip(b"=")
        .decode("ascii")
    )


def _decode_bytes(value: str) -> bytes:
    """
    Decode URL-safe Base64 without padding.
    """
    padded = value + "=" * (-len(value) % 4)

    return base64.urlsafe_b64decode(padded)

def hash_password(password: str) -> str:
   
 

    if not password:
        raise ValueError("Password cannot be empty")
    if len(password) > 128:
        raise ValueError("Password is too long")

    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PASSWORD_ITERATIONS,
    )

    return "$".join(
        (
            _PASSWORD_ALGORITHM,
            str(_PASSWORD_ITERATIONS),
            _encode_bytes(salt),
            _encode_bytes(digest),
        )
    )


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    

    if not plain_password or not hashed_password:
        return False

    try:
        (
            algorithm,
            iterations,
            encoded_salt,
            encoded_digest,
        ) = hashed_password.split("$", 3)

        if algorithm != _PASSWORD_ALGORITHM:
            return False

        iterations = int(iterations)

        if iterations <= 0:
            return False

        salt = _decode_bytes(encoded_salt)
        expected_digest = _decode_bytes(encoded_digest)

        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(
            actual_digest,
            expected_digest,
        )

    except (
        TypeError,
        ValueError,
        UnicodeError,
    ):
        return False

def _sign(payload: dict[str, Any]) -> str:
    
    

    header = _encode_part(
        {
            "alg": _TOKEN_ALGORITHM,
            "typ": "JWT",
            "ver": _TOKEN_VERSION,
        }
    )

    body = _encode_part(payload)

    message = f"{header}.{body}".encode("utf-8")

    signature = hmac.new(
        _secret_key(),
        message,
        hashlib.sha256,
    ).digest()

    encoded_signature = _encode_bytes(signature)

    return f"{header}.{body}.{encoded_signature}"

def create_access_token(
    subject: int | str,
    expires_delta: timedelta | None = None,
    claims: dict[str, Any] | None = None,
) -> str:

    now = datetime.now(timezone.utc)

    expires = now + (
        expires_delta
        or timedelta(minutes=_ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_urlsafe(16),
    }

    if claims:
        reserved_claims = {"sub", "type", "iat", "exp", "jti"}
        if reserved_claims.intersection(claims):
            raise ValueError("Claims cannot override reserved token fields")
        payload.update(claims)

    return _sign(payload)


def create_refresh_token(
    subject: int | str,
    expires_delta: timedelta | None = None,
) -> str:
   
    now = datetime.now(timezone.utc)

    expires = now + (
        expires_delta
        or timedelta(days=_REFRESH_TOKEN_EXPIRE_DAYS)
    )

    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_urlsafe(16),
    }

    return _sign(payload)

def _decode_token(
    token: str,
    expected_type: str | None = None,
) -> dict[str, Any]:
   
    
   

    try:
        parts = token.split(".")

        if len(parts) != 3:
            raise ValueError("Invalid token structure")

        encoded_header, encoded_body, encoded_signature = parts
        header = _decode_part(encoded_header)

        if not isinstance(header, dict):
            raise ValueError("Invalid token header")

        if header.get("alg") != _TOKEN_ALGORITHM:
            raise ValueError("Unsupported token algorithm")

        if header.get("typ") != "JWT":
            raise ValueError("Invalid token type")

        if header.get("ver") != _TOKEN_VERSION:
            raise ValueError("Unsupported token version")
        
        message = (
            f"{encoded_header}.{encoded_body}"
        ).encode("utf-8")

        expected_signature = hmac.new(
            _secret_key(),
            message,
            hashlib.sha256,
        ).digest()

        provided_signature = _decode_bytes(
            encoded_signature
        )

        if not hmac.compare_digest(
            provided_signature,
            expected_signature,
        ):
            raise ValueError("Invalid token signature")

        payload = _decode_part(encoded_body)

        if not isinstance(payload, dict):
            raise ValueError("Invalid token payload")

        subject = payload.get("sub")
        token_type = payload.get("type")
        issued_at = payload.get("iat")
        expires_at = payload.get("exp")
        token_id = payload.get("jti")

        if not subject:
            raise ValueError("Missing subject")

        if not token_type:
            raise ValueError("Missing token type")

        if issued_at is None:
            raise ValueError("Missing issued-at timestamp")

        if expires_at is None:
            raise ValueError("Missing expiration")

        if not token_id:
            raise ValueError("Missing token ID")

        current_time = int(time.time())

        if not isinstance(issued_at, int) or not isinstance(expires_at, int):
            raise ValueError("Invalid expiration")

        if issued_at > current_time + 60:
            raise ValueError("Token issued in the future")

        if expires_at <= current_time:
            raise ValueError("Token has expired")


        if token_id in _REVOKED_TOKEN_IDS:
            raise ValueError("Token has been revoked")

     

        if (
            expected_type is not None
            and token_type != expected_type
        ):
            raise ValueError("Unexpected token type")

        return payload

    except (
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        json.JSONDecodeError,
    ):
        raise ValueError("Invalid token") from None
    
def register_user(
    db: Session,
    user: UserCreate,
) -> User:
    
    existing_username = (
        db.query(User)
        .filter(User.user_name == user.user_name)
        .first()
    )

    if existing_username is not None:
        raise ValueError("Username is already in use")

    

    email = str(user.email)

    existing_email = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if existing_email is not None:
        raise ValueError("Email is already in use")

    

    db_user = User(
        user_name=user.user_name,
        email=email,
        password=hash_password(user.password),
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user
    
def authenticate_user(
    db: Session,
    username_or_email: str,
    password: str,
) -> User | None:
    
    

   
        
        
    

    user = (
        db.query(User)
        .filter(
            (User.user_name == username_or_email)
            | (User.email == username_or_email)
        )
        .first()
    )

    if user is None:
        return None

    if not verify_password(
        password,
        str(user.password),
    ):
        return None

    return user


def login_user(
    db: Session,
    username_or_email: str,
    password: str,
) -> dict[str, str] | None:
    

    user = authenticate_user(
        db,
        username_or_email,
        password,
    )

    if user is None:
        return None

    access_token = create_access_token(
        subject=str(user.id)
    )

    refresh_token = create_refresh_token(
        subject=str(user.id)
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

def refresh_access_token(
    refresh_token: str,
) -> dict[str, str]:
    
    
    

    payload = _decode_token(
        refresh_token,
        expected_type="refresh",
    )
    _REVOKED_TOKEN_IDS.add(str(payload["jti"]))

    return {
        "access_token": create_access_token(subject=payload["sub"]),
        "refresh_token": create_refresh_token(subject=payload["sub"]),
        "token_type": "bearer",
    }


def verify_token(
    token: str,
    token_type: str = "access",
) -> dict[str, Any]:
    

    return _decode_token(
        token,
        expected_type=token_type,
    )

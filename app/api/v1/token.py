"""
BuildOS Auth Service
Token API
"""

from fastapi import APIRouter, HTTPException, Request, status

from app.api.dependencies import TokenServiceDependency
from app.core.exceptions import (
    ExpiredTokenError,
    InvalidTokenError,
    RevokedTokenError,
)
from app.schemas.token import (
    TokenRefreshRequest,
    TokenRefreshResponse,
    TokenRevokeRequest,
    TokenRevokeResponse,
)

router = APIRouter()


@router.post(
    "/refresh",
    response_model=TokenRefreshResponse,
    status_code=status.HTTP_200_OK,
)
def refresh_token(
    payload: TokenRefreshRequest,
    request: Request,
    token_service: TokenServiceDependency,
) -> TokenRefreshResponse:
    """
    Rotate a refresh token and issue a new token pair.
    """

    try:
        token_pair = token_service.refresh(
            refresh_token=payload.refresh_token,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except ExpiredTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired.",
        ) from exc
    except RevokedTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked.",
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        ) from exc

    return TokenRefreshResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        token_type=token_pair.token_type,
    )


@router.post(
    "/revoke",
    response_model=TokenRevokeResponse,
    status_code=status.HTTP_200_OK,
)
def revoke_token(
    payload: TokenRevokeRequest,
    request: Request,
    token_service: TokenServiceDependency,
) -> TokenRevokeResponse:
    """
    Revoke a single refresh token.
    """

    try:
        token_service.revoke(
            refresh_token=payload.refresh_token,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except ExpiredTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired.",
        ) from exc
    except RevokedTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has already been revoked.",
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        ) from exc

    return TokenRevokeResponse(
        revoked=True,
    )

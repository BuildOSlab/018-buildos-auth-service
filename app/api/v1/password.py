"""
BuildOS Auth Service
Password API
"""

from fastapi import APIRouter, HTTPException, Request, status

from app.api.dependencies import (
    CurrentUserContextDependency,
    PasswordServiceDependency,
)
from app.core.exceptions import InvalidCredentialsError, PasswordResetError
from app.schemas.password import (
    ChangePasswordRequest,
    ChangePasswordResponse,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetRequest,
    PasswordResetRequestResponse,
)
from app.services.password_service import PasswordContext

router = APIRouter()


@router.post(
    "/change",
    response_model=ChangePasswordResponse,
    status_code=status.HTTP_200_OK,
)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    password_service: PasswordServiceDependency,
    current_user: CurrentUserContextDependency,
) -> ChangePasswordResponse:
    """Change the authenticated user's password."""

    try:
        result = password_service.change_password(
            user_id=current_user.user_id,
            current_password=payload.current_password,
            new_password=payload.new_password,
            context=PasswordContext(
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            ),
        )
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    return ChangePasswordResponse(
        changed=result.changed,
        user_id=result.user_id,
    )


@router.post(
    "/reset/request",
    response_model=PasswordResetRequestResponse,
    status_code=status.HTTP_200_OK,
)
def request_password_reset(
    payload: PasswordResetRequest,
    request: Request,
    password_service: PasswordServiceDependency,
) -> PasswordResetRequestResponse:
    """Request a password reset without revealing account existence."""

    result = password_service.request_reset(
        identifier=payload.identifier,
        ip_address=request.client.host if request.client else None,
    )

    return PasswordResetRequestResponse(
        requested=result.requested,
    )


@router.post(
    "/reset/confirm",
    response_model=PasswordResetConfirmResponse,
    status_code=status.HTTP_200_OK,
)
def confirm_password_reset(
    payload: PasswordResetConfirmRequest,
    request: Request,
    password_service: PasswordServiceDependency,
) -> PasswordResetConfirmResponse:
    """Complete a password reset using a valid reset token."""

    try:
        result = password_service.confirm_reset(
            reset_token=payload.reset_token,
            new_password=payload.new_password,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except PasswordResetError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return PasswordResetConfirmResponse(
        reset=result.reset,
        user_id=result.user_id,
    )

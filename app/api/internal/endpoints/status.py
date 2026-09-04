"""
BuildOS Auth Service
Internal status synchronization endpoint.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.dependencies import (
    DatabaseSession,
    verify_internal_service,
)
from app.repositories.credential_repository import CredentialRepository
from app.services.credential_sync_service import CredentialSyncService

router = APIRouter(
    prefix="/internal/auth/users",
    tags=["Internal Status Sync"],
)


class UserStatusUpdateRequest(BaseModel):
    """Request body for status update from 019."""

    user_id: UUID
    status: str
    is_active: bool


class UserStatusUpdateResponse(BaseModel):
    """Response returned after credential synchronization."""

    success: bool


@router.post(
    "/{user_id}/status",
    status_code=status.HTTP_200_OK,
    response_model=UserStatusUpdateResponse,
    dependencies=[Depends(verify_internal_service)],
)
def update_user_status(
    user_id: UUID,
    payload: UserStatusUpdateRequest,
    db: DatabaseSession,
) -> UserStatusUpdateResponse:
    """
    Synchronize authentication credential state with user status.
    """

    if user_id != payload.user_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="User ID in path does not match request body.",
        )

    credential_repository = CredentialRepository(db)
    sync_service = CredentialSyncService(credential_repository)

    try:
        sync_service.sync_status(
            user_id=user_id,
            user_status=payload.status,
            is_active=payload.is_active,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to synchronize credential status.",
        ) from exc

    return UserStatusUpdateResponse(success=True)

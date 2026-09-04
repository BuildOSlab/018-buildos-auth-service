"""
BuildOS Auth Service
Internal API Router
"""

from fastapi import APIRouter

from app.api.internal.endpoints.status import router as status_router

router = APIRouter()

router.include_router(status_router)

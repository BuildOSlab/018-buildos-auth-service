"""
BuildOS Auth Service
API v1 Router
"""

from fastapi import APIRouter

from app.api.v1 import auth, password, security, token

router = APIRouter(prefix="/v1")

router.include_router(
    auth.router,
    prefix="/auth",
    tags=["authentication"],
)

router.include_router(
    password.router,
    prefix="/password",
    tags=["password"],
)

router.include_router(
    security.router,
    prefix="/security",
    tags=["security"],
)

router.include_router(
    token.router,
    prefix="/token",
    tags=["token"],
)

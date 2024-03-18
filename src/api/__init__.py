from fastapi import APIRouter

from .auth import router as auth_router
from .accounts import router as accounts_router
from .oauth import router as oauth_router


router = APIRouter()

router.include_router(auth_router)
router.include_router(accounts_router)
router.include_router(oauth_router)

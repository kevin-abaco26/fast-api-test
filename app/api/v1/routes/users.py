from fastapi import APIRouter

from app.dependencies import CurrentUser
from app.schemas.auth import MessageResponse

router = APIRouter(tags=["users"])


@router.get("/account/role", response_model=MessageResponse)
def get_role(current_user: CurrentUser):
    role_name = current_user.roles[0].name if current_user.roles else ""
    return MessageResponse(message=role_name)

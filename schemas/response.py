from pydantic import BaseModel
from typing import Optional, Any, Literal

class APIResponse(BaseModel):
    """Standard API response schema for all endpoints"""
    status: Literal["success", "fail"]
    message: str
    data: Optional[Any] = None
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class UserProfile(BaseModel):
    """Model for user profile data"""

    username: str = Field(..., min_length=3, max_length=50)
    email: Optional[str] = Field(None, regex=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    age: Optional[int] = Field(None, ge=0, le=120)


class Order(BaseModel):
    """Model for order data"""

    order_id: str = Field(..., min_length=5, max_length=20)
    product: str
    quantity: int = Field(..., gt=0)

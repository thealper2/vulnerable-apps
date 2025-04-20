import re

from pydantic import BaseModel, constr, validator

from config import Config


class UserLogin(BaseModel):
    """Validation model for user login"""
    username: constr(max_length=Config.MAX_INPUT_LENGTH)
    password: constr(max_length=Config.MAX_INPUT_LENGTH)
    
    @validator('username')
    def validate_username_chars(cls, v):
        if not re.match(Config.ALLOWED_CHARS, v):
            raise ValueError("Username contains invalid characters")
        return v
    
    @validator('password')
    def validate_password_chars(cls, v):
        if not re.match(Config.ALLOWED_CHARS, v):
            raise ValueError("Password contains invalid characters")
        return v

class UserCreate(UserLogin):
    """Validation model for user creation"""
    email: constr(max_length=100)
    
    @validator('email')
    def validate_email(cls, v):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v

class UserResponse(BaseModel):
    """Response model for user data"""
    id: int
    username: str
    email: str
    
    class Config:
        orm_mode = True
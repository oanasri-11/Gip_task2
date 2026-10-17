from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserBase(BaseModel):
  user_name: str = Field(min_length=3, max_length=50)
  email: EmailStr

class UserCreate(UserBase):
  password: str = Field(min_length=12, max_length=128)

class UserOut(BaseModel):
  id: int
  user_name: str
  email: str
  email_verified: bool
  
  model_config = ConfigDict(from_attributes=True)
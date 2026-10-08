from pydantic import BaseModel, EmailStr, Field

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class UrlInput(BaseModel):
    url: str = Field(min_length=8, max_length=2048)

class EmailInput(BaseModel):
    content: str = Field(min_length=1, max_length=2_000_000)

class CopilotInput(BaseModel):
    scan_id: int
    question: str = Field(min_length=1, max_length=2000)

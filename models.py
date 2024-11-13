from sqlmodel import Field, Session, SQLModel, create_engine, select
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Query
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
from pydantic import BaseModel
def hash_password(password: str):
    return pwd_context.hash(password)

def get_session():
    with Session(engine) as session:
        yield session
SessionDep = Annotated[Session, Depends(get_session)]

class Hero(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    age: int | None = Field(default=None, index=True)
    secret_name: str



class UserBase(SQLModel):
    email: str | None = Field(index=True)  # Add the email field here
    username: str | None = Field(default=None)


class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    password: str
    
class UserPublic(UserBase):
    id: int

class CreateUser(UserBase):
    password: str



sqlite_file_name = "tasks.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)



def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


# To declare a request body, you use Pydantic models with all their power and benefits.


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


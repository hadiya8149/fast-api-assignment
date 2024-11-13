from fastapi import FastAPI

from fastapi import Depends, FastAPI, HTTPException, Query
from models import *
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


@app.on_event("startup")
def on_startup():
    create_db_and_tables()

@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/items/{item_id}")
async def read_item(item_id: int):
    return {"item_id": item_id}

@app.post("/heroes/")
def create_hero(hero: Hero, session: SessionDep) -> Hero:
    session.add(hero)
    session.commit()
    session.refresh(hero)
    return hero

@app.get("/heroes/{hero_id}")
def read_hero(hero_id: int, session: SessionDep) -> Hero:
    hero = session.get(Hero, hero_id)
    if not hero:
        raise HTTPException(status_code=404, detail="Hero not found")
    return hero




@app.post('/signup', response_model=UserPublic)
def signup_user(user: CreateUser,session: SessionDep):
    hashed_password = hash_password(user.password)
    user.password = hashed_password
    new_user = User.model_validate(user)
    session.add(new_user)
    session.commit()
    session.refresh(new_user) 
    return new_user




@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}

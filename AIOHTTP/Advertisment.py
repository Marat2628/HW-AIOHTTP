import asyncio
import json
from aiohttp import web
from bcrypt import hashpw, gensalt, checkpw
from sqlalchemy import Column, Integer, String, DateTime, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError


PG_DSN = "postgresql+asyncpg://WEBPY-58:22334455@127.0.0.1:5435/HomeWork_AIOHTTP"
engine = create_async_engine(PG_DSN)
Session = sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)

Base = declarative_base()


class User(Base):
    __tablename__ = "Advertisment"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    owner = Column(String(30), nullable=False)
    password = Column(String, nullable=False)


app = web.Application()


async def orm_context(app: web.Application):
    print("START")
    async with engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all)
        # await conn.commit()
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()
    print("SHUTDOWN")


@web.middleware
async def session_middleware(requests: web.Request, handler):
    async with Session() as session:
        requests["session"] = session
        return await handler(requests)


app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)


def hash_password(password: str):
    password = password.encode()
    password = hashpw(password, salt=gensalt())
    return password.decode()


async def get_user(user_id: int, session: Session):
    user = await session.get(User, user_id)

    if user is None:
        raise web.HTTPNotFound(
            text=json.dumps({"status": "error", "message": "user not found"}),
            content_type="application/json",
        )

    return user


class UserView(web.View):
    async def get(self):
        '''Получить объявление от сервера'''
        session = self.request["session"]
        user_id = int(self.request.match_info["user_id"])
        user = await get_user(user_id, session)
        unicodeData = {
                "id": user.id,
                "title": user.title,
                "description": user.description,
                "owner": user.owner,
                "created_at": user.created_at.isoformat(),
            }
        encodedUnicode = json.dumps(unicodeData, ensure_ascii=False)

        return web.json_response(encodedUnicode, content_type="application/json")


    async def post(self):
        '''Отправить объявление от клиента к серверу'''
        session = self.request["session"]
        json_data = await self.request.json()
        json_data["password"] = hash_password(json_data["password"])
        user = User(**json_data)
        session.add(user)
        try:
            await session.commit()
        except IntegrityError as er:
            raise web.HTTPConflict(
                text=json.dumps({"status": "error", "message": "user already exists"}),
                content_type="application/json",
            )

        return web.json_response({"id": user.id})

    async def patch(self):
        '''Изменить объявление'''
        user_id = int(self.request.match_info["user_id"])
        user = await get_user(user_id, self.request["session"])
        json_data = await self.request.json()
        if "password" in json_data:
            json_data["password"] = hash_password(json_data["password"])
        for field, value in json_data.items():
            setattr(user, field, value)
        self.request["session"].add(user)
        await self.request["session"].commit()
        return web.json_response({"status": "success"})

    async def delete(self):
        '''Удалить объявление'''
        user_id = int(self.request.match_info["user_id"])
        user = await get_user(user_id, self.request["session"])
        await self.request["session"].delete(user)
        await self.request["session"].commit()
        return web.json_response({"status": "success"})


app.add_routes(
    [
        web.get("/ad/{user_id:\d+}/", UserView),
        web.post("/ad/", UserView),
        web.patch("/ad/{user_id:\d+}/", UserView),
        web.delete("/ad/{user_id:\d+}/", UserView),
    ]
)

if __name__ == "__main__":
    web.run_app(app)

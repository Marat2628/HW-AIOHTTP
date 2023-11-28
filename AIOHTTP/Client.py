import json
import asyncio
from aiohttp import ClientSession


async def main():
    async with ClientSession() as session:
        response = await session.post('http://127.0.0.1:8080/ad/', json={ "title": "Продам люстру",
                                                                          "description": "Люстра черная лофт",
                                                                          "owner": "Галина М.",
                                                                          "password": "pass007766"},)
        print(response.status)
        print(await response.text())


        response = await session.patch('http://127.0.0.1:8080/ad/4/', json={"title": "Продам ламинат!!!!",
                                                                         "description": "Ламинат цвет ольха lite",
                                                                         "owner": "Svetlana",
                                                                         "password": "pass0859209"}, )
        print(response.status)
        print(await response.text())


        response = await session.delete('http://127.0.0.1:8080/ad/4/')
        print(response.status)
        print(await response.text())

        response = await session.get('http://127.0.0.1:8080/ad/2/')
        print(response.status)
        print(await response.text())


asyncio.run(main())
import html

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, PlainTextResponse
from starlette.routing import Route


async def welcome(request):
    who = request.query_params.get("who", "")
    return HTMLResponse("<h1>Welcome " + html.escape(who) + "</h1>")


async def welcome_text(request):
    who = request.query_params.get("who", "")
    return PlainTextResponse("Welcome " + who)


app = Starlette(routes=[Route("/welcome", welcome), Route("/welcome.txt", welcome_text)])

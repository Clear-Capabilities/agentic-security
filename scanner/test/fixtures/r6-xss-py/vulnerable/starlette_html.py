from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.routing import Route


async def welcome(request):
    who = request.query_params.get("who", "")
    return HTMLResponse("<h1>Welcome " + who + "</h1>")


app = Starlette(routes=[Route("/welcome", welcome)])

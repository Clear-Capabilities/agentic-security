from starlette.responses import FileResponse

async def download(request):
    return FileResponse('/srv/files/' + request.query_params['f'])
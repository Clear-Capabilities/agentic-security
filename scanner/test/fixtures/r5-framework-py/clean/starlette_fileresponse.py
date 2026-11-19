import os
from starlette.responses import FileResponse

async def download(request):
    return FileResponse(os.path.join('/srv/files', os.path.basename(request.query_params['f'])))
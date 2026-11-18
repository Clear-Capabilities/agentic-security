import json
from django.http import HttpResponse

def hello(request):
    return HttpResponse(json.dumps({'name': request.GET.get('name')}), content_type='application/json')
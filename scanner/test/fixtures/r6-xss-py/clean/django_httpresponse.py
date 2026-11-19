import json

from django.http import HttpResponse
from django.utils.html import escape


def search(request):
    q = request.GET.get("q", "")
    return HttpResponse("<h2>Results for " + escape(q) + "</h2>")


def search_api(request):
    q = request.GET.get("q", "")
    return HttpResponse(json.dumps({"q": q}), content_type="application/json")

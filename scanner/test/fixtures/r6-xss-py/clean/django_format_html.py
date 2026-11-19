from django.http import HttpResponse
from django.utils.html import format_html


def greet(request):
    name = request.GET.get("name", "")
    return HttpResponse(format_html("<p>Hello {}</p>", name))

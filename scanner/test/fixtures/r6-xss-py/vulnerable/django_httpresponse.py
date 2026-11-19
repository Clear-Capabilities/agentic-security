from django.http import HttpResponse


def search(request):
    q = request.GET.get("q", "")
    return HttpResponse("<h2>Results for " + q + "</h2>")

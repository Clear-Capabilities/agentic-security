from django.http import HttpResponse

def hello(request):
    return HttpResponse('<p>Hello ' + request.GET.get('name') + '</p>')
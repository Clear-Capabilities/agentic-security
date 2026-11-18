from django.http import HttpResponseRedirect

def go(request):
    return HttpResponseRedirect(request.GET.get('next'))
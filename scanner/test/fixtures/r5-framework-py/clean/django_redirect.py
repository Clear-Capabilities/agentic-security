from django.http import HttpResponseRedirect

def go(request):
    return HttpResponseRedirect('/home')
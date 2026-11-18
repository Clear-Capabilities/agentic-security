from django.shortcuts import get_object_or_404, render

from .models import Document, SiteSettings

SETTINGS_ROW = 1


def site_banner(request):
    settings = get_object_or_404(SiteSettings, pk=SETTINGS_ROW)
    return render(request, 'banner.html', {'settings': settings})


def search(request):
    pk = request.GET.get('q')
    results = Document.objects.filter(title__icontains=pk, owner=request.user)
    return render(request, 'results.html', {'results': results})

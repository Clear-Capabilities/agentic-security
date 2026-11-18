from django.shortcuts import get_object_or_404, render

from .models import Document


def show(request):
    doc_id = request.GET.get('id')
    doc = get_object_or_404(Document, pk=doc_id)
    return render(request, 'doc.html', {'doc': doc})

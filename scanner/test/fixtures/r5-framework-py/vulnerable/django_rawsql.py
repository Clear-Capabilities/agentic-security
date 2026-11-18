from django.db.models.expressions import RawSQL

def report(request):
    col = request.GET['col']
    return Order.objects.annotate(v=RawSQL('SELECT ' + col + ' FROM orders', []))
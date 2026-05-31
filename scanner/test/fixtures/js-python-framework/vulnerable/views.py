from .models import User
def list_users(request):
    col = request.GET.get("order_by", "id")
    return User.objects.raw("SELECT id, name FROM auth_user ORDER BY " + col)

from .models import User
ALLOWED = {"id", "name", "email"}
def list_users(request):
    col = request.GET.get("order_by", "id")
    if col not in ALLOWED:
        raise ValueError("bad column")
    return User.objects.all().order_by(col)

from django.http import HttpResponse
from django.template import loader
from django.utils.safestring import mark_safe


def profile(request):
    bio = request.GET.get("bio", "")
    safe_bio = mark_safe("<p class='bio'>" + bio + "</p>")
    template = loader.get_template("profile.html")
    return HttpResponse(template.render({"bio": safe_bio}, request))

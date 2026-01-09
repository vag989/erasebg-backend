from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.http import JsonResponse


@ensure_csrf_cookie
@csrf_exempt
def get_csrf(request):
    return JsonResponse(
        {
            "message": "CSRF cookie set",
            "success": True,
        }
    )

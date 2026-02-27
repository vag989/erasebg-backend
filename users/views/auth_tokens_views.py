from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from users.models import APIKey
from users.authentication import JWTCookieAuthentication

from erasebg.settings import DEBUG, COOKIE_SETTINGS, WORKER_COOKIE_SETTINGS
from erasebg.api.CONFIG import MESSAGES


class JWTTokenRefreshView(APIView):
    """
    Handles refreshing tokens for JWT
    """

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "refresh_access_token"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def post(self, request):
        """
        Post request to generate an access token
        """
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response(
                {
                    "message": MESSAGES["REFRESH_TOKEN_MISSING"],
                    "success": False,
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            response = Response(
                {
                    "message": MESSAGES["ACCESS_TOKEN_GENERATED"],
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )

            # set access token cookie for api calls to backend
            # set access token cookie for api calls to backend
            response.set_cookie(
                key="access_token",
                value=access_token,
                domain=COOKIE_SETTINGS.get("DOMAIN"),
                max_age=COOKIE_SETTINGS["ACCESS_TOKEN_VALIDITY"],
                httponly=COOKIE_SETTINGS["HTTP_ONLY"],
                secure=COOKIE_SETTINGS["SECURE_COOKIE"],
                samesite=COOKIE_SETTINGS["SAME_SITE"],
                path="/api/",
            )

            # # set access token cookie for api calls to worker
            # response.set_cookie(
            #     key="access_token",
            #     value=access_token,
            #     domain=WORKER_COOKIE_SETTINGS["DOMAIN"],
            #     max_age=WORKER_COOKIE_SETTINGS["ACCESS_TOKEN_VALIDITY"],
            #     httponly=WORKER_COOKIE_SETTINGS["HTTP_ONLY"],
            #     secure=WORKER_COOKIE_SETTINGS["SECURE_COOKIE"],
            #     samesite=WORKER_COOKIE_SETTINGS["SAME_SITE"],
            #     path="/",
            # )

            return response

        except TokenError as e:
            return Response(
                {
                    "message": MESSAGES["REFRESH_TOKEN_INVALID_OR_EXPIRED"],
                    "success": False,
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        

class APITokenView(APIView):
    """
    View to generate API Tokens to users if
    the token does not exist or return if it does
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "fetch_api_token"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def post (self, request, *args, **kwargs):
        """
        Post request to generate an API token 
        for an existing user
        """
        user = request.user

        try:
            token, created = APIKey.objects.get_or_create(user=user)
            if created:
                return Response(
                    {
                        "message": "API token generated successfully",
                        "success": True,
                        "token": token.key
                    },
                        status=status.HTTP_201_CREATED)
            else:
                return Response(
                    {
                        "message": "API token already exists", 
                        "success": True,
                        "token": token.key,
                    },
                        status=status.HTTP_200_OK)
                
        except Exception as e:
            return Response(
                {
                    "error": str(e),
                    "success": False,
                },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

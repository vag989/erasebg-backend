from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle

from rest_framework_simplejwt.tokens import RefreshToken

from datetime import timedelta

from users.models import CustomUser
from users.serializers import LogInSerializer
from users.authentication import JWTCookieAuthentication

from erasebg.api.CONFIG import MESSAGES, REMEMBER_ME_DAYS
from erasebg.settings import DEBUG, COOKIE_SETTINGS, WORKER_COOKIE_SETTINGS


class UserLoginView(APIView):
    """
    View handling user logins
    """

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "signup"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def post(self, request, *args, **kwargs):
        """
        Post method to handle login request
        """
        serializer = LogInSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "message": MESSAGES["LOGIN_FAILED_MESSAGE"],
                    "errors": serializer.errors,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        username = serializer.validated_data.get("username")
        email = serializer.validated_data.get("email")
        password = serializer.validated_data.get("password")
        remember_me = serializer.validated_data.get("remember_me")

        if not username:
            if email:
                try:
                    username = CustomUser.objects.get(email=email).username
                except ObjectDoesNotExist:
                    return Response(
                        {
                            "message": MESSAGES["LOGIN_FAILED_MESSAGE"],
                            "success": False,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return Response(
                    {
                        "message": MESSAGES["LOGIN_FAILED_MESSAGE"],
                        "success": False,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        user = authenticate(username=username, password=password)

        if not user:
            return Response(
                {
                    "message": MESSAGES["LOGIN_FAILED_MESSAGE"],
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        if not user.email_verification_token.verified:
            return Response(
                {
                    "message": MESSAGES["EMAIL_NOT_VERIFIED_MESSAGE"],
                    "success": False,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        CustomUser.objects.filter(username=username).select_for_update().update(
            last_login=timezone.now()
        )

        refresh = RefreshToken.for_user(user)
        if remember_me:
            refresh.set_exp(lifetime=timedelta(days=REMEMBER_ME_DAYS))
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response = Response(
            {
                "message": MESSAGES["LOGIN_SUCCESS_MESSAGE"],
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "member_since": user.date_joined.strftime("%Y-%m-%d %H:%M:%S GMT"),
                "success": True,
            },
            status=status.HTTP_200_OK,
        )

        # print(f'{type(COOKIE_SETTINGS['HTTP_ONLY'])} {COOKIE_SETTINGS['HTTP_ONLY']}')
        # print(f'{type(COOKIE_SETTINGS['SECURE_COOKIE'])} {COOKIE_SETTINGS['SECURE_COOKIE']}')
        # print(f'{type(COOKIE_SETTINGS['SAME_SITE'])} {COOKIE_SETTINGS['SAME_SITE']}')

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
        #     path="/api/",
        # )

        # set refresh token cookie for api calls to backend
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            domain=COOKIE_SETTINGS.get("DOMAIN"),
            max_age=COOKIE_SETTINGS["REFRESH_TOKEN_VALIDITY"],
            httponly=COOKIE_SETTINGS["HTTP_ONLY"],
            secure=COOKIE_SETTINGS["SECURE_COOKIE"],
            samesite=COOKIE_SETTINGS["SAME_SITE"],
            path="/api/users/auth-token/refresh/",
        )

        return response


class UserLogoutView(APIView):
    """
    View to handle user logout
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "signup"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def post(self, request, *args, **kwargs):
        """
        Post request to handle logout request
        by deleting http_only cookies
        """
        user = request.user

        response = Response(
            {
                "message": MESSAGES["LOGOUT_SUCCESS_MESSAGE"],
                "success": True,
            },
            status=status.HTTP_200_OK,
        )

        response.delete_cookie(
            key="access_token",
            domain=COOKIE_SETTINGS.get("DOMAIN"),
            samesite=COOKIE_SETTINGS["SAME_SITE"],
            path="/api/",
        )

        # # set access token cookie for api calls to worker
        # response.delete_cookie(
        #     key="access_token",
        #     domain=WORKER_COOKIE_SETTINGS["DOMAIN"],
        #     samesite=WORKER_COOKIE_SETTINGS["SAME_SITE"],
        #     path="/api/",
        # )

        # set refresh token cookie for api calls to backend
        response.delete_cookie(
            key="refresh_token",
            domain=COOKIE_SETTINGS.get("DOMAIN"),
            samesite=COOKIE_SETTINGS["SAME_SITE"],
            path="/api/users/auth-token/refresh/",
        )

        return response

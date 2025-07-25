
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken

from users.models import CustomUser

from erasebg.api.constants import MESSAGES
from erasebg.settings import COOKIE_SETTINGS, WORKER_COOKIE_SETTINGS


class UserLoginView(APIView):
    """
    View handling user logins
    """

    def post(self, request, *args, **kwargs):
        """
        Post method to handle login request
        """
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        if not username:
            if email:
                try:
                    username=CustomUser.objects.get(email=email).username
                except ObjectDoesNotExist:
                    return Response(
                        {
                            "message": MESSAGES["LOGIN_FAILED_MESSAGE"],
                            "success": False,
                        },
                            status=status.HTTP_400_BAD_REQUEST)
            else:
                Response(
                    {
                        "message": MESSAGES["LOGIN_FAILED_MESSAGE"],
                        "success": False,
                    },
                        status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response = Response(
                {
                    "message": MESSAGES["LOGIN_SUCCESS_MESSAGE"],
                    "success": True,
                },
                    status=status.HTTP_200_OK)

            print(f'{type(COOKIE_SETTINGS['HTTP_ONLY'])} {COOKIE_SETTINGS['HTTP_ONLY']}')
            print(f'{type(COOKIE_SETTINGS['SECURE_COOKIE'])} {COOKIE_SETTINGS['SECURE_COOKIE']}')
            print(f'{type(COOKIE_SETTINGS['SAME_SITE'])} {COOKIE_SETTINGS['SAME_SITE']}')

            # set access token cookie for api calls to backend
            response.set_cookie(
                key="access_token",
                value=access_token,
                max_age=COOKIE_SETTINGS['ACCESS_TOKEN_VALIDITY'],
                httponly=COOKIE_SETTINGS['HTTP_ONLY'],
                secure=COOKIE_SETTINGS['SECURE_COOKIE'],
                samesite=COOKIE_SETTINGS['SAME_SITE'],
                path="/api/removebg/",
            )

            # set access token cookie for api calls to worker
            response.set_cookie(
                key="access_token",
                value=access_token,
                domain=WORKER_COOKIE_SETTINGS["DOMAIN"],
                max_age=WORKER_COOKIE_SETTINGS['ACCESS_TOKEN_VALIDITY'],
                httponly=WORKER_COOKIE_SETTINGS['HTTP_ONLY'],
                secure=WORKER_COOKIE_SETTINGS['SECURE_COOKIE'],
                samesite=WORKER_COOKIE_SETTINGS['SAME_SITE'],
                path="/",
            )

            # set refresh token cookie for api calls to backend
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                max_age=COOKIE_SETTINGS['REFRESH_TOEKN_VALIDITY'],
                httponly=COOKIE_SETTINGS['HTTP_ONLY'],
                secure=COOKIE_SETTINGS['SECURE_COOKIE'],
                samesite=COOKIE_SETTINGS['SAME_SITE'],
                path="/api/users/token/refresh/",
            )

            return response

        return Response(
            {
                "message": MESSAGES["LOGIN_FAILED_MESSAGE"],
                "success": False,
            },
                status=status.HTTP_400_BAD_REQUEST)


class UserLogoutView(APIView):
    """
    View to handle user logout
    """
    def post(self, request, *args, **kwargs):
        """
        Post request to handle logout request
        by deleting http_only cookies
        """
        response = Response(
            {
                "message": MESSAGES["LOGOUT_SUCCESS_MESSAGE"],
                "success": True,
            },
                status=status.HTTP_200_OK)

        # Clear cookies
        response.delete_cookie("access_token", path="/api/removebg/")
        response.delete_cookie("refresh_token", path="/api/users/token/refresh/")

        return response

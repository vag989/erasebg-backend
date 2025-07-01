"""
Users related views
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist

from users.serializers import UserSerializer
from users.models import CustomUser

from simple.api.constants import MESSAGES
from simple.settings import COOKIE_SETTINGS


class UserSignUpView(APIView):
    """
    View handling user signups
    """
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": MESSAGES["SIGNUP_SUCCESS_MESSAGE"]},
                            status=status.HTTP_201_CREATED)

        return Response(serializer.errors,
                        status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """
    View handling user logins
    """
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        if not username:
            if email:
                try:
                    username=CustomUser.objects.get(email=email).username
                except ObjectDoesNotExist:
                    return Response({"message": MESSAGES["LOGIN_FAILED_MESSAGE"]},
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                Response({"message": MESSAGES["LOGIN_FAILED_MESSAGE"]},
                         status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response = Response({
                'message': MESSAGES["LOGIN_SUCCESS_MESSAGE"],
            })

            print(f'{type(COOKIE_SETTINGS['HTTP_ONLY'])} {COOKIE_SETTINGS['HTTP_ONLY']}')
            print(f'{type(COOKIE_SETTINGS['SECURE_COOKIE'])} {COOKIE_SETTINGS['SECURE_COOKIE']}')
            print(f'{type(COOKIE_SETTINGS['SAME_SITE'])} {COOKIE_SETTINGS['SAME_SITE']}')
   
            response.set_cookie(
                key="access_token",
                value=access_token,
                max_age=COOKIE_SETTINGS['ACCESS_TOKEN_VALIDITY'],
                httponly=COOKIE_SETTINGS['HTTP_ONLY'],
                secure=COOKIE_SETTINGS['SECURE_COOKIE'],
                samesite=COOKIE_SETTINGS['SAME_SITE'],
                path="/api/removebg/",
            )

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

        return Response({"message": MESSAGES["LOGIN_FAILED_MESSAGE"]},
                        status=status.HTTP_400_BAD_REQUEST)


class TokenRefreshView(APIView):
    """
    Handles refreshing tokens for JWT
    """
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            response = Response({
                "message": MESSAGES["ACCESS_TOKEN_GENERATED"],
            })

            response.set_cookie(
                key="access_token",
                value=access_token,
                max_age=COOKIE_SETTINGS['ACCESS_TOKEN_VALIDITY'],
                httponly=COOKIE_SETTINGS['HTTP_ONLY'],
                secure=COOKIE_SETTINGS['SECURE_COOKIE'],
                samesite=COOKIE_SETTINGS['SAME_SITE'],
                path="/api/removebg/",
            )
            return response

        except Exception:
            return Response({"message": MESSAGES["ACCESS_TOKEN_GENERATION_FAILED"]},
                            status=status.HTTP_400_BAD_REQUEST)

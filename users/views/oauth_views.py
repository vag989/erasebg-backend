from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle

# from users.models import APIToken
from users.models import CustomUser, APIKey, EmailVerificationTokens
from users.serializers import UserSerializer, UserEmailVerificationSerializer, RequestVerificationEmailResendSerializer
from users.utils.resend import send_verification_email

# https://medium.com/@abhaykanwasi/building-google-authentication-with-jwt-in-django-and-react-a2f71ec02432


# class GoogleOAuthView(APIView):
#     """
#     Implements Google OAuth View for login and signup
#     """

#     def get_throttles(self):
#         if not DEBUG:
            
#         return super().get_throttles()

#     def post(self, request, *args, **kwargs):
#         """
#         Post method to handle
#         Google oauth login / signup
#         """

#         serializer = GoogleLoginSerializer(data=request.data)
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import F

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle

from users.models import CustomUser, PasswordResetOTP
from users.serializers import (
    GetOTPSerializer,
    VerifyOTPSerializer,
    UpdatePasswordSerializer,
)
from users.utils.resend import send_password_reset_otp

from erasebg.api.CONFIG import (
    MESSAGES,
    OTP_MAX_INCORRECT_ATTEMPTS,
)
from erasebg.settings import DEBUG, COOKIE_SETTINGS


class GetOTPView(APIView):
    """
    View to get otp for password reset
    """

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [AnonRateThrottle]
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def post(self, request, *args, **kwargs):
        """
        Post method to fetch otp for password reset
        """
        serializer = GetOTPSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {"errors": serializer.errors, "success": False},
                status=status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data.get("email")

        try:
            user = CustomUser.objects.get(email=email)

            otp_entries = PasswordResetOTP.objects.filter(user=user)

            if (
                not otp_entries.exists()
                or otp_entries[0].is_expired
                or otp_entries[0].incorrect_count >= OTP_MAX_INCORRECT_ATTEMPTS
            ):
                PasswordResetOTP.objects.filter(user=user).delete()
                PasswordResetOTP.objects.create(user=user)

            if not DEBUG:
                send_password_reset_otp(
                    to_email=email,
                    otp=user.password_reset_otp.otp,
                )

            return Response(
                {
                    "message": MESSAGES["OTP_SENT"],
                    "email": email,
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )

        except ObjectDoesNotExist:
            return Response(
                {
                    "message": MESSAGES["EMAIL_NOT_FOUND"],
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class VerifyOTPView(APIView):
    """
    View to verify OTP for password reset
    """

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [AnonRateThrottle]
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def post(self, request, *args, **kwargs):
        """
        Post method to verify password reset otp
        """
        serializer = VerifyOTPSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "errors": serializer.errors,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data.get("email")
        otp = serializer.validated_data.get("otp")

        user_exists = False

        try:
            user = CustomUser.objects.get(email=email)
            user_exists = True

            otp_entry = user.password_reset_otp

            if (
                otp_entry.is_expired
                or otp_entry.incorrect_count >= OTP_MAX_INCORRECT_ATTEMPTS
            ):
                return Response(
                    {
                        "message": MESSAGES["OTP_MAX_INCORRECT"],
                        "otp_max_attempts": not otp_entry.is_expired,
                        "otp_expired": otp_entry.is_expired,
                        "success": False,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if otp == otp_entry.otp:
                response = Response(
                    {
                        "message": MESSAGES["OTP_VERIFICATION_SUCCESSFUL"],
                        "success": True,
                    },
                    status=status.HTTP_200_OK,
                )

                response.set_cookie(
                    key="password_update_token",
                    value=otp_entry.password_reset_token,
                    max_age=COOKIE_SETTINGS["ACCESS_TOKEN_VALIDITY"],
                    domain=COOKIE_SETTINGS["DOMAIN"],
                    httponly=COOKIE_SETTINGS["HTTP_ONLY"],
                    secure=COOKIE_SETTINGS["SECURE_COOKIE"],
                    samesite=COOKIE_SETTINGS["SAME_SITE"],
                    path="/api/users/reset-password/update-password/",
                )

                return response

            PasswordResetOTP.objects.filter(user=user).select_for_update().update(
                incorrect_count=F("incorrect_count") + 1
            )

            return Response(
                {
                    "message": MESSAGES["OTP_VERIFICATION_UNSUCCESSFUL"],
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        except ObjectDoesNotExist as e:
            message = (
                MESSAGES["OTP_NOT_FOUND"]
                if user_exists
                else MESSAGES["EMAIL_NOT_FOUND"]
            )

            return Response(
                {
                    "message": message,
                    "email_invalid": not user_exists,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class UpdatePasswordView(APIView):
    """
    View to update the password to a new password
    """

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [AnonRateThrottle]
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def patch(self, request, *args, **kwargs):
        """
        Patch methods to update the password to a new password
        """

        serializer = UpdatePasswordSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "errors": serializer.errors,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data.get("email")
        new_password = serializer.validated_data.get("new_password")
        password_update_token = request.COOKIES.get("password_update_token")

        try:
            user = CustomUser.objects.get(email=email)
            otp_entry = user.password_reset_otp

            if otp_entry.password_reset_token != password_update_token:
                response = Response(
                    {
                        "message": MESSAGES["PASSWORD_UPDATE_TOKEN_INVALID"],
                        "success": False,
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            else:
                user.set_password(new_password)
                user.save()

                otp_entry.delete()

                response = Response(
                    {
                        "message": MESSAGES["PASSWORD_UPDATE_SUCCESSFUL"],
                        "success": True,
                    },
                    status=status.HTTP_200_OK,
                )

            response.delete_cookie(
                key="password_update_token",
                path="/api/users/reset-password/update-password/",
            )
            return response

        except ObjectDoesNotExist:
            return Response(
                {
                    "message": MESSAGES["EMAIL_NOT_FOUND"],
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

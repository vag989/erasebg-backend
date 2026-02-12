from django.core.exceptions import ObjectDoesNotExist
from django.db.models import F

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from users.models import CustomUser, PasswordResetOTP
from users.serializers import (
    GetOTPSerializer,
    RequestVerificationEmailResendSerializer
)
from users.utils.resend import send_password_reset_otp

from erasebg.api.CONFIG import (
    MESSAGES,
    OTP_MAX_INCORRECT_ATTEMPTS,
)
from erasebg.settings import DEBUG, COOKIE_SETTINGS


class GetOTPHelperView(APIView):
    """
    View to get otp for password reset
    """

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

            return Response(
                {
                    "otp": user.password_reset_otp.otp,
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
        

class GetVerificationLinkHelperView(APIView):
    """
    View handling resending verification email
    """

    def post(self, request, *args, **kwargs):
        """
        Handle resending verification email
        """
        serializer = RequestVerificationEmailResendSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "message": MESSAGES["RESEND_VERIFICATION_EMAIL_FAILED"],
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data["email"]
        user = CustomUser.objects.filter(email=email).first()

        if not user:
            return Response(
                {
                    "message": MESSAGES["RESEND_VERIFICATION_EMAIL_NOT_FOUND"],
                    "email_not_found": True,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        if user.email_verification_token.verified:
            return Response(
                {
                    "message": MESSAGES["EMAIL_ALREADY_VERIFIED"],
                    "already_verified": True,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        verification_token=user.email_verification_token.verification_token,

        return Response(
            {
                "verification_token": verification_token,
                "success": True,
            },
            status=status.HTTP_200_OK,
        )
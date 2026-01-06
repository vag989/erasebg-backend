from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle

# from users.models import APIToken
from users.models import CustomUser, APIToken, EmailVerificationTokens
from users.serializers import UserSerializer, UserEmailVerificationSerializer, RequestVerificationEmailResendSerializer
from users.utils.resend import send_verification_email

from erasebg.api.CONFIG import MESSAGES
from erasebg.settings import DEBUG

from users.utils.resend import send_verification_email


class UserSignUpView(APIView):
    """
    View handling user signups
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
        Handle user signup
        """
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            APIToken.objects.create(user=serializer.instance)
            EmailVerificationTokens.objects.create(user=serializer.instance)

            if not DEBUG:
                send_verification_email(
                    to_email=serializer.instance.email,
                    verification_token=serializer.instance.email_verification_token.verification_token,
                )

            return Response(
                {
                    "message": MESSAGES["SIGNUP_SUCCESS_MESSAGE"],
                    "user": serializer.data,
                    "success": True,
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {
                "errors": str(serializer.errors),
                "success": False,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class ResendVerificationEmail(APIView):
    """
    View handling resending verification email
    """

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "resend_verification_email"
        else:
            self.throttle_classes = []
        return super().get_throttles()

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
        
        if not DEBUG:
            send_verification_email(
                to_email=user.email,
                verification_token=user.email_verification_token.verification_token,
            )

        return Response(
            {
                "message": MESSAGES["RESEND_VERIFICATION_EMAIL_SUCCESS"],
                "success": True,
            },
            status=status.HTTP_200_OK,
        )


class UserEmailVerificationView(APIView):
    """
    View handling user email verification
    """

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "email_verification"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def get(self, request, *args, **kwargs):
        """
        Handle email verification
        """
        serializer = UserEmailVerificationSerializer(data=request.query_params)

        location = "/html/email-verification-status"

        # 302 status code is what helps browser to redirect
        if not serializer.is_valid():
            location += "?status=failure"
            return Response(
                headers={"Location": location}, status=status.HTTP_302_FOUND
            )

        email = serializer.validated_data["email"]
        verification_token = serializer.validated_data["verification_token"]

        user = CustomUser.objects.filter(email=email)[0]

        if verification_token == user.email_verification_token.verification_token:
            location += "?status=success"
            user.email_verification_token.verified = True
            user.email_verification_token.save(update_fields=["verified"])
            status_code = status.HTTP_200_OK
        else :
            location += "?status=failure"

        return Response(headers={"Location": location}, status=status.HTTP_302_FOUND)

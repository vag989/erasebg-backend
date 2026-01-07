from django.utils import timezone

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle

# from rest_framework_simplejwt.authentication import JWTAuthentication

from users.serializers import CreditsSerializer
from users.authentication import JWTCookieAuthentication

from erasebg.api.CONFIG import MESSAGES
from erasebg.settings import DEBUG


class CreditsView(APIView):
    """
    View to manage credits
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "fetch_credits"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve
        credits for a user
        """
        user = request.user

        credits = user.credits.filter(expires__gt=timezone.now()).order_by("created")

        if not credits.exists():
            return Response(
                {
                    "message": MESSAGES["CREDITS_UNAVAILABLE"],
                    "success": False,
                },
                status=status.HTTP_402_PAYMENT_REQUIRED,
            )

        serializer = CreditsSerializer(credits, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class BulkCreditsView(APIView):
    """
    View to manage bulk credits
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "fetch_bulk_credits"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve
        bulk credits for a user
        """
        user = request.user

        credits = user.bulk_credits.filter(expires__gt=timezone.now()).order_by(
            "created"
        )

        if not credits.exists():
            return Response(
                {
                    "message": MESSAGES["CREDITS_UNAVAILABLE"],
                    "success": False,
                },
                status=status.HTTP_402_PAYMENT_REQUIRED,
            )

        serializer = CreditsSerializer(credits, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class APICreditsView(APIView):
    """
    View to manage API credits
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "fetch_api_credits"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve API
        credits for a user
        """
        user = request.user

        credits = user.api_credits.filter(expires__gt=timezone.now()).order_by(
            "created"
        )

        if not credits.exists():
            return Response(
                {
                    "message": MESSAGES["CREDITS_UNAVAILABLE"],
                    "success": False,
                },
                status=status.HTTP_402_PAYMENT_REQUIRED,
            )

        serializer = CreditsSerializer(credits, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

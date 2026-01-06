from django.db.utils import IntegrityError

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle

from users.authentication import JWTCookieAuthentication
from users.serializers import UpdateDetailsSerializer

from erasebg.api.CONFIG import MESSAGES
from erasebg.settings import DEBUG


class UserDetailsView(APIView):
    """
    View for getting user details
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "fetch_user_details"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def get(self, request, *args, **kwargs):
        user = request.user

        return Response(
            {
                "message": MESSAGES["USER_DETAILS_FETCHED"],
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "member_since": user.date_joined.strftime("%Y-%m-%d %H:%M:%S GMT"),
                "success": True,
            },
            status=status.HTTP_200_OK,
        )
 

class UpdateDetailsView(APIView):
    """
    View for updating user details
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "update_user_details"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def patch(self, request, *args, **kwargs):
        user = request.user

        serializer = UpdateDetailsSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "errors": serializer.errors,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        first_name = serializer.validated_data.get("first_name")
        last_name = serializer.validated_data.get("last_name")
        email = serializer.validated_data.get("email")

        try:
            if first_name:
                user.first_name = first_name
            if last_name:
                user.last_name = last_name
            if email:
                user.email = email

            user.save()

            return Response(
                {
                    "message": MESSAGES["USER_DETAILS_UPDATED"],
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )

        except IntegrityError as e:
            return Response(
                {
                    "message": MESSAGES["USER_DETAILS_NON_UNIQUE_EMAIL"],
                    "errors": str(e),
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

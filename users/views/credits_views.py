from django.core.exceptions import ObjectDoesNotExist

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

# from rest_framework_simplejwt.authentication import JWTAuthentication

from users.models import Credits, BulkCredits, APICredits
from users.serializers import CreditsSerializer
from users.authentication import JWTCookieAuthentication

from simple.api.constants import MESSAGES
from simple.settings import DEBUG

class CreditsView(APIView):
    """
    View to manage credits
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve
        credits for a user 
        """
        user = request.user

        credits = user.credits.all().order_by('created')

        if not credits.exists():
            return Response(
                {
                    "message": MESSAGES["CREDITS_UNAVAILABLE"],
                    "success": False, 
                },
                    status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = CreditsSerializer(credits, many=True)

        return  Response(serializer.data, status=status.HTTP_200_OK)


class BulkCreditsView(APIView):
    """
    View to manage bulk credits
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve 
        bulk credits for a user 
        """
        user = request.user

        credits = user.bulk_credits.all().order_by('created')

        if not credits.exists():
            return Response(
                {
                    "message": MESSAGES["CREDITS_UNAVAILABLE"],
                    "success": False, 
                },
                    status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = CreditsSerializer(credits, many=True)

        return  Response(serializer.data, status=status.HTTP_200_OK)


class APICreditsView(APIView):
    """
    View to manage API credits
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTCookieAuthentication]

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve API
        credits for a user 
        """
        user = request.user

        credits = user.api_credits.all().order_by('created')

        if not credits.exists():
            return Response(
                {
                    "message": MESSAGES["CREDITS_UNAVAILABLE"],
                    "success": False, 
                },
                    status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = CreditsSerializer(credits, many=True)

        return  Response(serializer.data, status=status.HTTP_200_OK)

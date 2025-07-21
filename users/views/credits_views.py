from django.core.exceptions import ObjectDoesNotExist

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

from rest_framework_simplejwt.authentication import JWTAuthentication

from users.models import Credits, BulkCredits, APICredits
from users.serializers import CreditsSerializer, BulkCreditsSerializer, APICreditsSerializer

from simple.settings import DEBUG


class CreditsView(APIView):
    """
    View to manage credits
    """
    permission_classes = [IsAuthenticated] if not DEBUG else []
    authentication_classes = [JWTAuthentication] if not DEBUG else []

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve
        credits for a user 
        """
        user = request.user

        try:
            credits = Credits.objects.get(user=user)
            serializer = CreditsSerializer(credits, many=True)
        
            return  Response(serializer.data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            return Response(
                { 
                    "message": str(e),
                    "success": False,
                },
                    status=status.HTTP_400_BAD_REQUEST)
        

class BulkCreditsView(APIView):
    """
    View to manage bulk credits
    """
    permission_classes = [IsAuthenticated] if not DEBUG else []
    authentication_classes = [JWTAuthentication] if not DEBUG else []

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve 
        bulk credits for a user 
        """
        user = request.user

        try:
            credits = BulkCredits.objects.get(user=user)
            serializer = BulkCreditsSerializer(credits, many=True)
        
            return  Response(serializer.data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            return Response(
                { "message": str(e) }, 
                status=status.HTTP_400_BAD_REQUEST)


class APICreditsView(APIView):
    """
    View to manage API credits
    """
    permission_classes = [IsAuthenticated] if not DEBUG else []
    authentication_classes = [JWTAuthentication] if not DEBUG else []

    def get(self, request, *args, **kwargs):
        """
        Handles GET request to retrieve API
        credits for a user 
        """
        user = request.user

        try:
            credits = APICredits.objects.get(user=user)
            serializer = APICreditsSerializer(credits, many=True)
        
            return  Response(serializer.data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            return Response(
                { "message": str(e) }, 
                status=status.HTTP_400_BAD_REQUEST)






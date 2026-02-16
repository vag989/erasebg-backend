from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from users.models import CustomUser

from rest_framework_simplejwt.tokens import RefreshToken

from erasebg.settings import DEBUG


class AccessTokenHelperView(APIView):
    """
    Helper view to fetch access token
    """

    def post(self, request, *args, **kwargs):
        """
        POST method to get access token 
        """

        email = request.data.get("email")

        if not email:
            return Response(
                {
                    "message": "email is missing",
                    "success": False,
                },
                
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = CustomUser.objects.filter(email=email).first()

        if not user:
            return Response(
                {
                    "message": "user does not exist",
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        refresh = RefreshToken.for_user(user=user)
        
        return Response(
            {
                "access_token": str(refresh.access_token) if DEGUB else "corrupted_token",
                "success": True,
            },
            status=status.HTTP_200_OK
        )

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser, IsAuthenticated

# from rest_framework_simplejwt.authentication import JWTAuthentication

from payments.serializers import AddCreditsSerializer

from users.authentication import JWTCookieAuthentication
from users.models import CustomUser, Credits, BulkCredits

from simple.api.constants import MESSAGES

# ToDo: Temporary to be removed
class AddCreditsView(APIView):
    """
    View to Add credits to a user (temporary)
    """
    permission_classes = [IsAuthenticated, IsAdminUser]
    # authentication_classes = [JWTCookieAuthentication]

    def post(self, request, *args, **kwargs):
        """
        POST method to handle add credits request
        """

        serializer = AddCreditsSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "error": serializer.errors,
                    "success": False, 
                },
                    status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data["username"]
        num_credits = serializer.validated_data["num_credits"]

        try:
            user = CustomUser.objects.get(username=username)
            credit = Credits.objects.create(user=user, credits=num_credits)

            if credit:
                return Response(
                    {
                        "message": str(credit.credits) + ' ' + MESSAGES["CREDITS_ADDED"],
                        "num_credits": num_credits,
                        "success": True,
                    },
                        status=status.HTTP_200_OK
                )

            return Response(
                {
                    "message": MESSAGES["CREDITS_ADD_FAILED"],
                    "success": False,
                },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response(
                {
                    "message": str(e),
                    "success": False,
                },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ToDo: Temporary to be removed
class AddBulkCreditsView(APIView):
    """
    View to Add credits to a user (temporary)
    """
    permission_classes = [IsAuthenticated, IsAdminUser]
    # authentication_classes = [JWTCookieAuthentication]

    def post(self, request, *args, **kwargs):
        """
        POST method to handle add credits request
        """

        serializer = AddCreditsSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "error": serializer.errors,
                    "success": False, 
                },
                    status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data["username"]
        num_credits = serializer.validated_data["num_credits"]

        try:
            user = CustomUser.objects.get(username=username)
            credit = BulkCredits.objects.create(user=user, credits=num_credits)

            if credit:
                return Response(
                    {
                        "message": str(credit.credits) + ' ' + MESSAGES["CREDITS_ADDED"],
                        "num_credits": num_credits,
                        "success": True,
                    },
                        status=status.HTTP_200_OK
                )

            return Response(
                {
                    "message": MESSAGES["CREDITS_ADD_FAILED"],
                    "success": False,
                },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception:
            return Response(
                {
                    "message": MESSAGES["INTERNAL_ERROR"],
                    "success": False,
                },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

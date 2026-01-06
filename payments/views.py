from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle

# from rest_framework_simplejwt.authentication import JWTAuthentication

from payments.serializers import AddCreditsSerializer

from users.authentication import JWTCookieAuthentication
from users.models import CustomUser, Credits, BulkCredits, APICredits

from erasebg.api.CONFIG import MESSAGES
from erasebg.settings import DEBUG


# ToDo: Temporary to be removed
class AddCreditsView(APIView):
    """
    View to Add credits to a user (temporary)
    """
    permission_classes = [IsAuthenticated, IsAdminUser]
    # authentication_classes = [JWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "add_credits"
        else:
            self.throttle_classes = []
        return super().get_throttles()

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
        bulk_credits = serializer.validated_data.get("bulk_credits", 0)
        api_credits = serializer.validated_data.get("api_credits", 0)

        try:
            user = CustomUser.objects.get(username=username)
            Credits.objects.create(user=user, credits=num_credits)

            if bulk_credits:
                BulkCredits.objects.create(user=user, credits=bulk_credits)
            if api_credits:
                APICredits.objects.create(user=user, credits=api_credits)

            return Response(
                {
                    "message": MESSAGES["CREDITS_ADDED"],
                    "num_credits": num_credits,
                    "bulk_credits": bulk_credits,
                    "api_credits": api_credits,
                    "success": True,
                },
                    status=status.HTTP_200_OK
            )
        
        except Exception as e:
            return Response(
                {
                    "message": str(e),
                    "success": False,
                },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# # ToDo: Temporary to be removed
# class AddBulkCreditsView(APIView):
#     """
#     View to Add credits to a user (temporary)
#     """
#     permission_classes = [IsAuthenticated, IsAdminUser]
#     # authentication_classes = [JWTCookieAuthentication]

#     def get_throttles(self):
#         if not DEBUG:
#             self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
#             self.throttle_scope = "add_bulk_credits"
#         else:
#             self.throttle_classes = []
#         return super().get_throttles()

#     def post(self, request, *args, **kwargs):
#         """
#         POST method to handle add credits request
#         """

#         serializer = AddCreditsSerializer(data=request.data)

#         if not serializer.is_valid():
#             return Response(
#                 {
#                     "error": serializer.errors,
#                     "success": False, 
#                 },
#                     status=status.HTTP_400_BAD_REQUEST)

#         username = serializer.validated_data["username"]
#         num_credits = serializer.validated_data["num_credits"]

#         try:
#             user = CustomUser.objects.get(username=username)
#             credit = BulkCredits.objects.create(user=user, credits=num_credits)

#             if credit:
#                 return Response(
#                     {
#                         "message": str(credit.credits) + ' ' + MESSAGES["CREDITS_ADDED"],
#                         "num_credits": num_credits,
#                         "success": True,
#                     },
#                         status=status.HTTP_200_OK
#                 )

#             return Response(
#                 {
#                     "message": MESSAGES["CREDITS_ADD_FAILED"],
#                     "success": False,
#                 },
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
#         except Exception:
#             return Response(
#                 {
#                     "message": MESSAGES["INTERNAL_ERROR"],
#                     "success": False,
#                 },
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
        

# # ToDo: Temporary to be removed
# class AddAPICreditsView(APIView):
#     """
#     View to Add credits to a user (temporary)
#     """
#     permission_classes = [IsAuthenticated, IsAdminUser]
#     # authentication_classes = [JWTCookieAuthentication]

#     def get_throttles(self):
#         if not DEBUG:
#             self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
#             self.throttle_scope = "add_api_credits"
#         else:
#             self.throttle_classes = []
#         return super().get_throttles()

#     def post(self, request, *args, **kwargs):
#         """
#         POST method to handle add credits request
#         """

#         serializer = AddCreditsSerializer(data=request.data)

#         if not serializer.is_valid():
#             return Response(
#                 {
#                     "error": serializer.errors,
#                     "success": False, 
#                 },
#                     status=status.HTTP_400_BAD_REQUEST)

#         username = serializer.validated_data["username"]
#         num_credits = serializer.validated_data["num_credits"]

#         try:
#             user = CustomUser.objects.get(username=username)
#             credit = BulkCredits.objects.create(user=user, credits=num_credits)

#             if credit:
#                 return Response(
#                     {
#                         "message": str(credit.credits) + ' ' + MESSAGES["CREDITS_ADDED"],
#                         "num_credits": num_credits,
#                         "success": True,
#                     },
#                         status=status.HTTP_200_OK
#                 )

#             return Response(
#                 {
#                     "message": MESSAGES["CREDITS_ADD_FAILED"],
#                     "success": False,
#                 },
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
#         except Exception:
#             return Response(
#                 {
#                     "message": MESSAGES["INTERNAL_ERROR"],
#                     "success": False,
#                 },
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
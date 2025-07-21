

from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response

from users.models import APIToken
from users.serializers import UserSerializer

from simple.api.constants import MESSAGES


class UserSignUpView(APIView):
    """
    View handling user signups
    """
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            _, _ = APIToken.objects.get_or_create(
                user=serializer.instance)

            return Response(
                {
                    "message": MESSAGES["SIGNUP_SUCCESS_MESSAGE"],
                    "user": serializer.data,
                },
                status=status.HTTP_201_CREATED)

        return Response(serializer.errors,
                        status=status.HTTP_400_BAD_REQUEST)
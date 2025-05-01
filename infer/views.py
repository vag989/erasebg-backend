"""

"""

from io import BytesIO

from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from infer.serializers import EraseBGSerializer

from infer.services.replicate import erase_bg


class EraseBG(APIView):
    """
    Implements the view for image 
    background removal
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        """
        Handles post request to remove Image 
        backgrounds
        """ 
        serializer = EraseBGSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, 
                            status=status.HTTP_400_BAD_REQUEST)

        # Process the image with the inference service
        processed_image = erase_bg(serializer.data)

        # Save the processed image into a BytesIO object to return as a response
        img_io = BytesIO()
        processed_image.save(img_io, format='PNG')
        img_io.seek(0)

        # Return the processed image in the response
        response = Response(data=img_io.getvalue())
        response['Content-Type'] = 'image/png'
        return response
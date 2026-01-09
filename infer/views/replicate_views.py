# from io import BytesIO

# from django.http import HttpResponse


# from rest_framework import status
# from rest_framework.views import APIView
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.response import Response

# # from rest_framework_simplejwt.authentication import JWTAuthentication

# from infer.serializers import EraseBGSerializer, PollPredictionSerializer, FetchOutputSerializer
# from users.authentication import JWTCookieAuthentication
# from infer.services.replicate_service import erase_bg

# from erasebg.settings import DEBUG
# from erasebg.api.CONFIG import MESSAGES

# from PIL import Image

# import replicate
# import requests
# from requests.exceptions import Timeout
# from replicate.exceptions import ModelError, ReplicateError


# class EraseBGCreatePredicitonView(APIView):
#     """
#     Implements the view for image 
#     background removal
#     """

#     authentication_classes = [JWTCookieAuthentication]
#     permission_classes = [IsAuthenticated]
    
#     def post(self, request, *args, **kwargs):
#         """
#         Handles post request to remove Image 
#         backgrounds
#         """
        
#         if DEBUG:
#             print(f"Request Data: {request.data}")
#             print(f"Request Files: {request.FILES}")

#         serializer = EraseBGSerializer(data=request.data)

#         image = request.data.get('image')
#         # prompt = request.data.get('prompt')

#         if DEBUG:
#             print(f'image: {image}')
#             print(f'image type: {type(image)}')
#             # print(f'prompt: {prompt}')
#             # print(f'promt type: {type(prompt)}')

#         if not serializer.is_valid():
#             return Response(
#                 {
#                     "error": serializer.errors,
#                     "success": False,
#                 },
#                     status=status.HTTP_400_BAD_REQUEST)

#         image = serializer.validated_data['image']
#         # prompt = serializer.validated_data['prompt']

#         # Process the image with the inference service
#         # processed_image = erase_bg(image, prompt)
#         ret_val = erase_bg(image)

#         if isinstance(ret_val, Image.Image):
#             # Save the processed image into a BytesIO object to return as a response
#             img_io = BytesIO()
#             ret_val.save(img_io, format='PNG')
#             img_io.seek(0)
#             img_binary = img_io.getvalue()

#             # Return the processed image in the response
#             return HttpResponse(img_binary, content_type='image/jpeg')
        
#         if isinstance(ret_val, dict):
#             ret_val["success"] = True
#             return Response(ret_val, status=status.HTTP_200_OK)

#         return Response(
#             {
#                 "message": MESSAGES["INTERNAL_ERROR"],
#                 "success": False,
#             },
#             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class PollPredictionView(APIView):
#     """
#     Implements the view to poll 
#     a replicate prediction
#     """

#     authentication_classes = [JWTCookieAuthentication]
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         """
#         Handles post request to remove Image 
#         backgrounds
#         """
#         if DEBUG:
#             print(request.data)
#         serializer = PollPredictionSerializer(data=request.data)

#         if not serializer.is_valid():
#             if DEBUG:
#                 print("PollPredictionSerializer validation fail")
#             return Response(
#                 {
#                     "error": serializer.errors,
#                     "success": False,
#                 },
#                     status=status.HTTP_400_BAD_REQUEST)

#         prediction_id = serializer.validated_data['prediction_id']

#         try:
#             prediction = replicate.predictions.get(prediction_id)
#             prediction = dict(prediction)
#             prediction["success"] = "True"

#             return Response(prediction,
#                             status=status.HTTP_200_OK)

#         except (ReplicateError, ModelError) as e:
#             return Response(
#                 {
#                     "error": str(e),
#                     "success": False,
#                 },
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         except Exception as e:
#             return Response(
#                 {
#                     "error": str(e),
#                     "success": False,
#                 },
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class FetchOutputView(APIView):
#     """
#     Implements a view to fetch the 
#     output of replicate prediction given the url
#     """

#     authentication_classes = [JWTCookieAuthentication]
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         """
#         Handles the request to get
#         generated output from a prediction 
#         """

#         serializer = FetchOutputSerializer(data=request.data)

#         if not serializer.is_valid():
#             if DEBUG:
#                 print("FetchOutputSerializer validation fail")
#             return Response(
#                 {
#                     "error": serializer.errors,
#                     "success": False,
#                 },
#                     status=status.HTTP_400_BAD_REQUEST)

#         output_url = serializer.validated_data['output_url']

#         try:
#             response = requests.get(output_url, timeout=5)

#             if DEBUG:
#                 print(response.headers['Content-Type'])

#             return HttpResponse(response.content,
#                                 content_type=response.headers['Content-Type'])
#         except Timeout:
#             return Response(
#                 {
#                     "message": MESSAGES["FETCH_TIMEOUT_ERROR"],
#                     "success": False,
#                 },
#                     status=status.HTTP_408_REQUEST_TIMEOUT)
#         except Exception as e:
#             return Response(
#                 {
#                     "error": str(e), 
#                     "success": False,
#                 },
#                     status=status.HTTP_503_SERVICE_UNAVAILABLE)
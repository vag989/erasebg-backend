# from PIL import Image
# from typing import Dict

# from requests.exceptions import Timeout
# import replicate
# from django.core.files.uploadedfile import InMemoryUploadedFile

# from erasebg.api.CONFIG import REMOVE_BG_MODEL


# # def erase_bg(image: InMemoryUploadedFile, prompt: str) -> Dict[any, any]:
# #     """
# #     Function takes a PILLOW image as input
# #     and returns 

# #     Args:
# #         imageFile (InMemoryUploadedFile): Uploaded input Image file
# #         prompt (str): The prompt to be used to 
# #                       extract the foreground
# #     Returns: 
# #         bg_removed (Image.Image): Image with the 
# #         foreground extracted as per the prompt
# #     """
#         # input = {
#         #       'image': image,
#         #       'prompt': prompt
#         # }
# #     bg_removed = replicate.predictions.create(
# #         REMOVE_BG_MODEL,
# #         input = input
# #     )

# #     return dict(bg_removed)


# def erase_bg(image: InMemoryUploadedFile) -> Dict[str, any]:
#     """
#     Remove background from an image using Replicate's model.

#     Args:
#         image (InMemoryUploadedFile): Input image file

#     Returns:
#         Dict[str, any]: Prediction details from Replicate

#     Raises:
#         ValueError: If the image cannot be read or is invalid
#     """
#     image.seek(0)

#     input_data = {
#         "image": image.file,
#     }

#     prediction = replicate.predictions.create(
#         version=REMOVE_BG_MODEL,
#         input=input_data
#     )

#     return dict(prediction)


# # def erase_bg(image: Image.Image) -> Image.Image:
# #     """
# #     Function takes a PILLOW image as input
# #     and returns

# #     Args:
# #         image (PIL.Image.Image): Input Image file
# #         prompt (str): The prompt to be used to
# #                       extract the foreground
# #     Returns:
# #         bg_removed (Image.Image): Image
# #         converted to grayscale
# #     """
# #     from PIL import Image

# #     img = Image.open(image)
# #     bg_removed = img.convert('L')

# #     return bg_removed

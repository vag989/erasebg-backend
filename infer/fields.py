# """
# Implementation of a custom image field to ensure
# validation and preprocessing
# """

# import io

# from rest_framework import serializers
# from PIL import Image

# from infer.utils.image_utils import resize_image
# from simple.api.constants import ALLOWED_IMAGE_TYPES, MAX_WIDTH, MAX_HEIGHT


# class EraseBGImageField(serializers.ImageField):
#     """
#     A Custom field implemented to validate and 
#     """
#     def __init__(self, *args, **kwargs):
#         # Default allowed mime types
#         self.allowed_mimetypes = kwargs.pop('allowed_mimetypes',
#                                             ALLOWED_IMAGE_TYPES)
#         super().__init__(*args, **kwargs)

#     def to_internal_value(self, data):
#         # Step 1: Get the image file from request.FILES 
#         # (data is typically the file object here)
#         file = super().to_internal_value(data)

#         # Step 2: Verify the file is not empty
#         if not file:
#             raise serializers.ValidationError("No file uploaded.")

#         # Step 3: Verify that the file's MIME type is allowed
#         mime_type = file.content_type
#         if mime_type not in self.allowed_mimetypes:
#             raise serializers.ValidationError(
#                 f"Invalid file type. Allowed types: {
#                     ', '.join(self.allowed_mimetypes)}")

#         # Step 4: Open the image file with Pillow
#         try:
#             img = Image.open(file)
#         except Exception as e:
#             raise serializers.ValidationError("Invalid image file.") from e

#         # Step 5: Process the image (e.g., resize, convert to RGB, etc.)
#         img = img.convert("RGB")  # Optional: Convert image to RGB (if needed)
#         img = resize_image(img, MAX_WIDTH, MAX_HEIGHT)

#         # Step 6: Store the image in a BytesIO object
#         img_io = io.BytesIO()
#         img.save(img_io, format='JPEG')  # Save image as JPEG (you can choose a different format)
#         img_io.seek(0)  # Move the cursor to the start of the BytesIO object

#         # Return the BytesIO object
#         return img_io

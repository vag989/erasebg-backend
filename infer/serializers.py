"""
Serializers of infer
"""

from PIL import Image
from rest_framework import serializers

from simple.api.constants import DEFAULT_PROMPT, ALLOWED_IMAGE_TYPES


class EraseBGSerializer(serializers.Serializer):
    """
    Serializer to handle data for Erasing Background
    """
    image = serializers.ImageField()
    # prompt = serializers.CharField(
    #     required=False,
    #     default=DEFAULT_PROMPT)

    def validate_image(self, value):
        """Validate the uploaded image file."""
        # Check MIME type
        mime_type = value.content_type
        if mime_type not in ALLOWED_IMAGE_TYPES:
            raise serializers.ValidationError(
                'Invalid image format. Only ' \
                'JPG, PNG, or WebP are allowed.')

        # Validate the image using Pillow
        try:
            img = Image.open(value)
            img.verify()  # Verifies the image file is valid
        except (IOError, SyntaxError) as e:
            raise serializers.ValidationError(
                'The uploaded file is not a ' \
                'valid image.') from e

        return value


class PollPredictionSerializer(serializers.Serializer):
    """
    Serializer to handle data for polling
    replicate prediction
    """ 
    prediction_id = serializers.CharField()


class FetchOutputSerializer(serializers.Serializer):
    """
    Serializer to handle getting image 
    output of completed prediction
    """
    output_url = serializers.URLField()
from rest_framework import serializers

from erasebg.api.constants import USERNAME_MAX_LENGTH


class AddCreditsSerializer(serializers.Serializer):
    """
    Serializer class for add credits view
    """
    username = serializers.CharField(max_length=USERNAME_MAX_LENGTH)
    num_credits = serializers.IntegerField(min_value=1, default=100)
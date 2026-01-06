from rest_framework import serializers

from erasebg.api.CONFIG import USERNAME_MAX_LENGTH, DEFAULT_CREDITS_ADDED


class AddCreditsSerializer(serializers.Serializer):
    """
    Serializer class for add credits view
    """

    username = serializers.CharField(max_length=USERNAME_MAX_LENGTH)
    num_credits = serializers.IntegerField(min_value=1, default=DEFAULT_CREDITS_ADDED)
    bulk_credits = serializers.IntegerField(min_value=1, required=False)
    api_credits = serializers.IntegerField(min_value=1, required=False)

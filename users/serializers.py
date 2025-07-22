import re

from rest_framework import serializers
from rest_framework.authtoken.models import Token

from users.models import CustomUser, Credits, BulkCredits, APICredits

from simple.api.constants import MESSAGES


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for CustomUser Model
    """
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password']

    def validate_username(self, value):
        """
        Validates username to conatin
        following characters: a-z, A-Z, 0-9, [ ._- ]
        """
        # Regex pattern for validating username
        pattern = r'^[a-zA-Z](?!.*[_.-]{2})[a-zA-Z0-9._-]{7,31}$'

        if not re.match(pattern, value):
            raise serializers.ValidationError(
                MESSAGES['VALIDATION_ERROR_USERNAME']
            )
        return value

    def create(self, validated_data):
        # Hash the password before creating the user
        user = CustomUser(
            username=validated_data['username'],
            email=validated_data['email'],
        )

        user.set_password(validated_data['password'])  # Hashing the password
        user.save()
        return user
    

class CreditsSerializer(serializers.ModelSerializer):
    """
    Serializer for Credits model
    """
    username = serializers.ReadOnlyField(source='user.username')

    class Meta:
        model = Credits
        fields = ['username', 'credits', 'created', 'expires']


class ValidateAccessTokenSerializer(serializers.Serializer):
    """
    Serializer to validate access token
    """
    access_token = serializers.CharField(
        help_text="Access token to validate user access"
    )

    def validate_access_token(self, value):
        """
        Validate the access token format.
        """
        if not value or len(value) < 10:
            raise serializers.ValidationError(
                "Invalid access token provided."
            )
        return value

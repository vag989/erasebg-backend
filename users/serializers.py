import re

from rest_framework import serializers

from users.models import CustomUser

from simple.api.constants import MESSAGES

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer to save user data
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

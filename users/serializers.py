import re

from rest_framework import serializers
from rest_framework.authtoken.models import Token

from users.models import CustomUser, Credits, BulkCredits, APICredits

from erasebg.api.CONFIG import (
    MESSAGES,
    USER_FL_NAME_MAX_LENGTH,
    USERNAME_MIN_LENGTH,
    USERNAME_MAX_LENGTH,
    OTP_LENGTH,
)


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for CustomUser Model
    """

    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ["username", "email", "password"]

    def validate_username(self, value):
        """
        Validates username to conatin
        following characters: a-z, 0-9, [ ._- ]
        """
        # Regex pattern for validating username
        pattern = r"^[a-z](?!.*[_.-]{2})[a-z0-9._-]{7,31}$"

        if not re.match(pattern, value):
            raise serializers.ValidationError(MESSAGES["VALIDATION_ERROR_USERNAME"])
        return value

    def validate_password(self, value):
        """
        Validates password to ensure it contains:
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 1 number
        - Length between 8 and 32 characters
        """
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,32}$"
        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and be 8-32 characters long."
            )
        return value

    def create(self, validated_data):
        # Hash the password before creating the user
        user = CustomUser(
            username=validated_data["username"],
            email=validated_data["email"],
        )

        user.set_password(validated_data["password"])  # Hashing the password
        user.save()
        return user


class LogInSerializer(serializers.Serializer):
    username = serializers.CharField(
        min_length=USERNAME_MIN_LENGTH, max_length=USERNAME_MAX_LENGTH, required=False
    )
    email = serializers.EmailField(required=False)
    password = serializers.CharField()
    remember_me = serializers.BooleanField(default=False)


class CreditsSerializer(serializers.ModelSerializer):
    """
    Serializer for Credits model
    """

    username = serializers.ReadOnlyField(source="user.username")

    class Meta:
        model = Credits
        fields = ["username", "credits", "created", "expires"]


class UpdateDetailsSerializer(serializers.Serializer):
    first_name = serializers.CharField(
        max_length=USER_FL_NAME_MAX_LENGTH, required=False
    )
    last_name = serializers.CharField(
        max_length=USER_FL_NAME_MAX_LENGTH, required=False
    )
    email = serializers.EmailField(required=False)


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
            raise serializers.ValidationError("Invalid access token provided.")
        return value


class RequestVerificationEmailResendSerializer(serializers.Serializer):
    """
    Serializer for requesting email verification
    """

    email = serializers.EmailField(required=True)


class UserEmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for user email verification
    """

    email = serializers.CharField(required=True)
    verification_token = serializers.CharField(required=True)


class GetOTPSerializer(serializers.Serializer):
    """
    Serializer for initiate password reset requests
    """

    email = serializers.EmailField(required=True)


class VerifyOTPSerializer(serializers.Serializer):
    """
    Serializer for verify otp requests
    """

    email = serializers.EmailField(required=True)
    otp = serializers.CharField(
        min_length=OTP_LENGTH, max_length=OTP_LENGTH, required=True
    )


class UpdatePasswordSerializer(serializers.Serializer):
    """
    Serializer for update password requests
    """

    email = serializers.EmailField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        """
        Validates password to ensure it contains:
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 1 number
        - Length between 8 and 32 characters
        """
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,32}$"
        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and be 8-32 characters long."
            )
        return value

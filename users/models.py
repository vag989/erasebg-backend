from datetime import timedelta

from random import randint

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

from rest_framework.authtoken.models import Token

from erasebg.settings import AUTH_USER_MODEL
from erasebg.api.CONFIG import (
    API_TOKEN_MAX_LENGTH,
    CREDITS_EXPIRY_DAYS,
    SUBSCRIPTION_PLANS,
    SUBSCRIPTION_TYPE_MAX_LENGTH,
    EMAIL_VERIFICATION_TOKEN_MAX_LENGTH,
    OTP_LENGTH,
    OTP_EXPIRY_MINUTES,
    PASSWORD_RESET_TOKEN_MAX_LENGTH,
)


class CustomUser(AbstractUser):
    """
    Model for user
    """

    email = models.EmailField(unique=True)


def get_credit_expiry_datetime():
    return timezone.now() + timedelta(days=CREDITS_EXPIRY_DAYS)


def get_otp_expiry_datetime():
    return timezone.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)


def get_otp():
    return str(randint(1000, 999999)).zfill(OTP_LENGTH)


class APIKey(models.Model):
    """
    Model for user associated API Token
    """

    user = models.OneToOneField(
        AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True
    )
    key = models.CharField(max_length=API_TOKEN_MAX_LENGTH, unique=True)
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.key:
            from rest_framework.authtoken.models import Token

            self.key = Token.generate_key()  # reuse DRF's key generator

        super().save(*args, **kwargs)


class Credits(models.Model):
    """
    Model to track user credits
    """

    user = models.ForeignKey(
        AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="credits"
    )
    credits = models.IntegerField(null=False)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(default=get_credit_expiry_datetime)

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    class Meta:
        ordering = ["created"]


class BulkCredits(models.Model):
    """
    Model to track user bulk remove credits
    """

    user = models.ForeignKey(
        AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="bulk_credits"
    )
    credits = models.IntegerField(null=False)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(default=get_credit_expiry_datetime)

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    class Meta:
        ordering = ["created"]


class APICredits(models.Model):
    """
    Model to track user API credits
    """

    user = models.ForeignKey(
        AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_credits"
    )
    credits = models.IntegerField(null=False)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(default=get_credit_expiry_datetime)

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    class Meta:
        ordering = ["created"]


class EmailVerificationTokens(models.Model):
    """
    Model to store Email verification tokens
    """

    user = models.OneToOneField(
        AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_verification_token",
    )
    verification_token = models.CharField(
        max_length=EMAIL_VERIFICATION_TOKEN_MAX_LENGTH, unique=True, null=False
    )
    verified = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.verification_token:
            self.verification_token = Token.generate_key()
        super().save(*args, **kwargs)


class PasswordResetOTP(models.Model):
    """
    Model to store OTPs for password reset
    """

    user = models.OneToOneField(
        AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="password_reset_otp"
    )
    otp = models.CharField(max_length=OTP_LENGTH, default=get_otp)
    password_reset_token = models.CharField(
        max_length=PASSWORD_RESET_TOKEN_MAX_LENGTH,
        unique=True,
    )
    incorrect_count = models.SmallIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(default=get_otp_expiry_datetime)

    @property
    def is_expired(self):
        """
        Property indicatinf if the OTP is expired
        """
        return timezone.now() > self.expires

    def save(self, *args, **kwargs):
        if not self.password_reset_token:
            self.password_reset_token = Token.generate_key()
        super().save(*args, **kwargs)

from datetime import timedelta

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

from rest_framework.authtoken.models import Token

from erasebg.settings import AUTH_USER_MODEL
from erasebg.api.constants import USERNAME_MAX_LENGTH, API_TOKEN_MAX_LENGTH, JOB_TOKEN_MAX_LENGTH, JOB_TOKEN_EXPIRY_MINUTES, CREDITS_EXPIRY_DAYS


class CustomUser(AbstractUser):
    """
    Model for user
    """
    email = models.EmailField(unique=True)


class APIToken(models.Model):
    """
    Model for user associated API Token 
    """
    user = models.OneToOneField(
        AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        primary_key=True
    )
    key = models.CharField(
        max_length=API_TOKEN_MAX_LENGTH,
        unique=True)
    created = models.DateTimeField(auto_now_add=True)
    username = models.CharField(max_length=150)

    def save(self, *args, **kwargs):
        if not self.key:
            from rest_framework.authtoken.models import Token
            self.key = Token.generate_key()  # reuse DRF's key generator
        if not self.username:
            self.username = self.user.username
        super().save(*args, **kwargs)


class Credits(models.Model):
    """
    Model to track user credits
    """
    user = models.ForeignKey(
        AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="credits"
        )
    credits = models.PositiveIntegerField(null=False)
    credits_in_use = models.PositiveIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(
        default=timezone.now() + timedelta(days=CREDITS_EXPIRY_DAYS)
    )

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    class Meta:
        ordering = ['created']


class BulkCredits(models.Model):
    """
    Model to track user bulk remove credits
    """
    user = models.ForeignKey(
        AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="bulk_credits"
        )
    credits = models.PositiveIntegerField(null=False)
    credits_in_use = models.PositiveIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(
        default=timezone.now() + timedelta(days=CREDITS_EXPIRY_DAYS))

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    class Meta:
        ordering = ['created']


class APICredits(models.Model):
    """
    Model to track user API credits
    """
    user = models.ForeignKey(
        AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_credits"
        )
    credits = models.PositiveIntegerField(null=False)
    credits_in_use = models.PositiveIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(
        default=timezone.now() + timedelta(days=CREDITS_EXPIRY_DAYS))

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    class Meta:
        ordering = ['created']

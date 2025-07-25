from datetime import timedelta

from django.db import models
from django.utils import timezone

from rest_framework.authtoken.models import Token

from users.models import Credits, BulkCredits

from erasebg.api.constants import JOB_TOKEN_MAX_LENGTH, JOB_TOKEN_EXPIRY_MINUTES
# from simple.settings import AUTH_USER_MODEL


# Create your models here.
class Jobs(models.Model):
    """
    Model to track single image processing jobs
    """
    credits = models.ForeignKey(
        Credits,
        on_delete=models.CASCADE
        )
    token = models.CharField(
        max_length=JOB_TOKEN_MAX_LENGTH,
        unique=True
        )
    expires = models.DateTimeField(
        default=timezone.now() + timedelta(minutes=JOB_TOKEN_EXPIRY_MINUTES)
    )

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = Token.generate_key()
        super().save(*args, **kwargs)

    class Meta:
        ordering = ['expires']


class BulkJobs(models.Model):
    """
    Model to track single image processing jobs
    """
    credits = models.ForeignKey(
        BulkCredits,
        on_delete=models.CASCADE
        )
    token = models.CharField(
        max_length=JOB_TOKEN_MAX_LENGTH,
        unique=True
        )
    expires = models.DateTimeField(
        default=timezone.now() + timedelta(minutes=JOB_TOKEN_EXPIRY_MINUTES)
    )

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = Token.generate_key()
        super().save(*args, **kwargs)

    class Meta:
        ordering = ['expires']

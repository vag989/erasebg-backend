from datetime import timedelta

from django.db import models
from django.utils import timezone

from rest_framework.authtoken.models import Token

from users.models import CustomUser

from erasebg.api.CONFIG import (
    JOB_TOKEN_MAX_LENGTH,
    JOB_TOKEN_EXPIRY_MINUTES,
    INFERENCE_COMPLETION_STATUS,
    INFERENCE_COMPLETION_STATUS_MAX_LENGTH,
)

# from simple.settings import AUTH_USER_MODEL


def get_expiry_time():
    return timezone.now() + timedelta(minutes=JOB_TOKEN_EXPIRY_MINUTES)


# Create your models here.
class Jobs(models.Model):
    """
    Model to track single image processing jobs
    """
    user = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name="inference_jobs"
    )
    job_token = models.CharField(max_length=JOB_TOKEN_MAX_LENGTH, unique=True)
    completion_status = models.CharField(
        choices=INFERENCE_COMPLETION_STATUS,
        max_length=INFERENCE_COMPLETION_STATUS_MAX_LENGTH,
        null=True,
    )
    completed_at = models.DateTimeField(null=True)
    expires = models.DateTimeField(default=get_expiry_time)

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    def save(self, *args, **kwargs):
        if not self.job_token:
            self.job_token = Token.generate_key()
        super().save(*args, **kwargs)

    class Meta:
        ordering = ["expires"]


class BulkJobs(models.Model):
    """
    Model to track bulk image processing jobs
    """
    user = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name="bulk_inference_jobs"
    )
    job_token = models.CharField(max_length=JOB_TOKEN_MAX_LENGTH, unique=True)
    completion_status = models.CharField(
        choices=INFERENCE_COMPLETION_STATUS,
        max_length=INFERENCE_COMPLETION_STATUS_MAX_LENGTH,
        null=True,
    )
    completed_at = models.DateTimeField(null=True)
    expires = models.DateTimeField(default=get_expiry_time)

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    def save(self, *args, **kwargs):
        if not self.job_token:
            self.job_token = Token.generate_key()
        super().save(*args, **kwargs)

    class Meta:
        ordering = ["expires"]


class APIJobs(models.Model):
    """
    Model to track API processing Jobs
    """
    user = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name="api_inference_jobs"
    )
    job_token = models.CharField(max_length=JOB_TOKEN_MAX_LENGTH, unique=True)
    completion_status = models.CharField(
        choices=INFERENCE_COMPLETION_STATUS,
        max_length=INFERENCE_COMPLETION_STATUS_MAX_LENGTH,
        null=True,
    )
    completed_at = models.DateTimeField(null=True)
    expires = models.DateTimeField(default=get_expiry_time)

    @property
    def is_expired(self):
        """
        Property indicating if the Job is expired
        """
        return timezone.now() > self.expires

    def save(self, *args, **kwargs):
        if not self.job_token:
            self.job_token = Token.generate_key()
        super().save(*args, **kwargs)

    class Meta:
        ordering = ["expires"]

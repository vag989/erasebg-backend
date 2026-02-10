"""
Credits related views required for inference
"""

from datetime import timedelta

from django.db.models import Sum, Count, F
from django.db import DatabaseError, transaction
from django.utils import timezone

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle, AnonRateThrottle

from infer.models import Jobs, BulkJobs, APIJobs
from infer.serializers import WrapUpInferenceSerializer
from infer.authentication import (
    WorkerHMACAuthentication,
    WorkerHMACAndJWTCookieAuthentication,
    WorkerHMACAndAPIKeyAuthentication
)

from users.models import CustomUser, Credits, BulkCredits, APICredits

from erasebg.settings import DEBUG
from erasebg.api.CONFIG import MESSAGES

from infer.utils.utils import tabulate_db_entries


class InitiateInferenceWorkerView(APIView):
    """
    View to check credits and allow
    inititation of inference
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [WorkerHMACAndJWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "initiate_inference_worker"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method handle inference initiation
        """
        user = request.user

        try:
            total_credits_available = (
                Credits.objects.filter(
                    user=user, credits__gt=0, expires__gt=timezone.now()
                )
                .select_for_update()
                .aggregate(total_credits=Sum("credits"))["total_credits"]
                or 0
            )

            active_jobs_count = (
                Jobs.objects.filter(
                    user=user, completed_at=None, expires__gt=timezone.now()
                ).count()
                or 0
            )

            if active_jobs_count >= total_credits_available:
                return Response(
                    {
                        "message": MESSAGES["CREDITS_UNAVAILABLE"],
                        "success": False,
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED,
                )

        except DatabaseError:
            return Response(
                {
                    "message": MESSAGES["SYSTEM_UNAVAILABLE"],
                    "success": False,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # # Decided not to use credits_in_use to track as it might need to be duducted for failed jobs
        # Credits.objects.filter(pk=credit_entry.pk).update(
        #     credits_in_use=F('credits_in_use') + 1
        # )

        job_token = Jobs.objects.create(user=user).job_token

        return Response(
            {
                "message": MESSAGES["CREDITS_AVAILABLE"],
                "job_token": job_token,
                "success": True,
            },
            status=status.HTTP_200_OK,
        )


class InitiateBulkInferenceWorkerView(APIView):
    """
    View to check Bulk credits and allow
    inititation of inference
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [WorkerHMACAndJWTCookieAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "initiate_bulk_inference_worker"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method handle Bulk inference initiation
        """
        user = request.user

        try:
            total_bulk_credits_available = (
                BulkCredits.objects.filter(
                    user=user, credits__gt=0, expires__gt=timezone.now()
                )
                .select_for_update()
                .aggregate(total_credits=Sum("credits"))["total_credits"]
                or 0
            )

            active_bulk_jobs_count = (
                BulkJobs.objects.filter(
                    user=user, completed_at=None, expires__gt=timezone.now()
                ).count()
                or 0
            )

            if active_bulk_jobs_count >= total_bulk_credits_available:
                return Response(
                    {
                        "message": MESSAGES["CREDITS_UNAVAILABLE"],
                        "success": False,
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED,
                )

        except DatabaseError:
            return Response(
                {
                    "message": MESSAGES["SYSTEM_UNAVAILABLE"],
                    "success": False,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # BulkCredits.objects.filter(pk=credit_entry.pk).update(
        #     credits_in_use=F("credits_in_use") + 1
        # )

        job_token = BulkJobs.objects.create(user=user).job_token

        return Response(
            {
                "message": MESSAGES["CREDITS_AVAILABLE"],
                "job_token": job_token,
                "success": True,
            },
            status=status.HTTP_200_OK,
        )


class InitiateAPIInferenceWorkerView(APIView):

    permission_classes = [IsAuthenticated]
    authentication_classes = [WorkerHMACAndAPIKeyAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "initiate_api_inference_worker"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def post(self, request, *args, **kwargs):
        """
        Post method to handle API Inference Initiation
        """
        user = request.user

        try:
            total_api_credits_available = (
                APICredits.objects.filter(
                    user=user, credits__gt=0, expires__gt=timezone.now()
                )
                .select_for_update()
                .aggregate(total_credits=Sum("credits"))["total_credits"]
                or 0
            )

            active_api_jobs_count = (
                APIJobs.objects.filter(
                    user=user, completed_at=None, expires__gt=timezone.now()
                ).count()
                or 0
            )

            if active_api_jobs_count >= total_api_credits_available:
                return Response(
                    {
                        "message": MESSAGES["CREDITS_UNAVAILABLE"],
                        "success": False,
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED,
                )

        except DatabaseError:
            return Response(
                {
                    "message": MESSAGES["SYSTEM_UNAVAILABLE"],
                    "success": False,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # BulkCredits.objects.filter(pk=credit_entry.pk).update(
        #     credits_in_use=F("credits_in_use") + 1
        # )

        job_token = APIJobs.objects.create(user=user).job_token

        return Response(
            {
                "message": MESSAGES["CREDITS_AVAILABLE"],
                "job_token": job_token,
                "success": True,
            },
            status=status.HTTP_200_OK,
        )


class WrapUpInferenceWorkerView(APIView):
    """
    View to wrap up inference cycle
    by deducting credits from the user
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [WorkerHMACAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "wrapup_inference_worker"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method to handle inference
        conclusion
        """
        serializer = WrapUpInferenceSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "error": serializer.errors,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        job_token = serializer.validated_data["job_token"]
        completion_status = serializer.validated_data["completion_status"]

        deduct_credits = 0 if completion_status != "COMPLETE" else 1

        try:
            job = Jobs.objects.filter(job_token=job_token).select_for_update().first()

            if not job or job.completed_at is not None:
                return Response(
                    {
                        "message": MESSAGES["JOB_DOES_NOT_EXIST"],
                        "success": False,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            job.completed_at = timezone.now()
            job.completion_status = completion_status
            job.save(update_fields=["completed_at", "completion_status"])

            user = CustomUser.objects.filter(pk=job.user_id).first()

            credit = (
                user.credits.filter(
                    user=user,
                    credits__gt=0,
                    expires__gt=timezone.now() - timedelta(seconds=20),
                )
                .select_for_update()
                .order_by("expires")
                .first()
            )

            if not credit or credit.credits <= 0:
                return Response(
                    {
                        "message": MESSAGES["CREDITS_NOT_DEDUCTED"],
                        "success": False,
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED,
                )

            credit.credits -= deduct_credits
            credit.save(update_fields=["credits"])

            return Response(
                {
                    "message": MESSAGES["CREDITS_DEDUCTED"],
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )

        except DatabaseError as e:
            return Response(
                {
                    "error": str(e),
                    "success": False,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class WrapUpBulkInferenceWorkerView(APIView):
    """
    View to warp up bulk inference cycle
    by deductiong credits from the user
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [WorkerHMACAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "wrapup_bulk_inference_worker"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method to handle Bulk inference
        conclusion
        """
        serializer = WrapUpInferenceSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "error": serializer.errors,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        bulk_job_token = serializer.validated_data["job_token"]
        completion_status = serializer.validated_data["completion_status"]

        deduct_credits = 0 if completion_status != "COMPLETE" else 1

        try:
            job = (
                BulkJobs.objects.filter(job_token=bulk_job_token)
                .select_for_update()
                .first()
            )

            if not job or job.completed_at is not None:
                return Response(
                    {
                        "message": MESSAGES["JOB_DOES_NOT_EXIST"],
                        "success": False,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            job.completed_at = timezone.now()
            job.completion_status = completion_status
            job.save(update_fields=["completed_at", "completion_status"])

            user = CustomUser.objects.filter(pk=job.user_id).first()

            credit = (
                user.bulk_credits.filter(
                    user=user,
                    credits__gt=0,
                    expires__gt=timezone.now() - timedelta(seconds=20),
                )
                .select_for_update()
                .order_by("expires")
                .first()
            )

            if not credit or credit.credits <= 0:
                return Response(
                    {
                        "message": MESSAGES["CREDITS_NOT_DEDUCTED"],
                        "success": False,
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED,
                )

            credit.credits -= deduct_credits
            credit.save(update_fields=["credits"])

            return Response(
                {
                    "message": MESSAGES["CREDITS_DEDUCTED"],
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )

        except DatabaseError as e:
            return Response(
                {
                    "error": str(e),
                    "success": False,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class WrapUpAPIInferenceWorkerView(APIView):
    """
    View to warp up api inference cycle
    by deductiong credits from the user
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [WorkerHMACAuthentication]

    def get_throttles(self):
        if not DEBUG:
            self.throttle_classes = [ScopedRateThrottle, AnonRateThrottle]
            self.throttle_scope = "wrapup_api_inference_worker"
        else:
            self.throttle_classes = []
        return super().get_throttles()

    def post(self, request, *args, **kwargs):
        """
        Post method to handle api inference
        conslusion fromm worker side
        """

        serializer = WrapUpInferenceSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "error": serializer.errors,
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        api_job_token = serializer.validated_data["job_token"]
        completion_status = serializer.validated_data["completion_status"]

        deduct_credits = 0 if completion_status != "COMPLETE" else 1

        try:
            job = (
                APIJobs.objects.filter(job_token=api_job_token).select_for_update().first()
            )

            if not job or job.completed_at is not None:
                return Response(
                    {
                        "message": MESSAGES["JOB_DOES_NOT_EXIST"],
                        "success": False,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            job.completed_at = timezone.now()
            job.completion_status = completion_status
            job.save(update_fields=["completed_at", "completion_status"])

            user = CustomUser.objects.filter(pk=job.user_id).first()

            credit = (
                user.api_credits.filter(
                    user=user,
                    credits__gt=0,
                    expires__gt=timezone.now() - timedelta(seconds=20),
                )
                .select_for_update()
                .order_by("expires")
                .first()
            )

            if not credit or credit.credits <= 0:
                return Response(
                    {
                        "message": MESSAGES["CREDITS_NOT_DEDUCTED"],
                        "success": False,
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED,
                )

            credit.credits -= deduct_credits
            credit.save(update_fields=["credits"])

            return Response(
                {
                    "message": MESSAGES["CREDITS_DEDUCTED"],
                    "success": True,
                },
                status=status.HTTP_200_OK,
            )

        except DatabaseError as e:
            return Response(
                {
                    "error": str(e),
                    "success": False,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

"""
Credits related views required for inference  
"""

from django.db.models import Sum, Count, F
from django.db import DatabaseError, transaction
from django.core.exceptions import ObjectDoesNotExist

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

# from rest_framework_simplejwt.authentication import JWTAuthentication

from infer.models import Jobs, BulkJobs
from infer.serializers import WrapUpInferenceSerializer

from users.models import Credits, BulkCredits
from users.authentication import JWTCookieAuthentication

from simple.settings import DEBUG, DB_LOCK_WAIT_TIMEOUT
from simple.api.constants import MESSAGES


from infer.utils.utils import tabulate_db_entries


class InitiateInferenceView(APIView):
    """
    View to check credits and allow 
    inititation of inference
    """
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JWTAuthentication]
    authentication_classes = [JWTCookieAuthentication]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method handle inference initiation
        """
        user = request.user

        try:
            credit_entry = (
                Credits.objects
                .filter(user=user)
                .select_for_update()
                .annotate(credits_available=F('credits') - F('credits_in_use'))
                .filter(credits_available__gt=0)
                .order_by('expires')
                .first()
            )
        except DatabaseError:
            return Response(
                {
                    "message": MESSAGES["SYSTEM_UNAVAILABLE"],
                    "success": False,
                },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        if not credit_entry:
            return Response(
            {
                "message": MESSAGES['CREDITS_UNAVAILABLE'],
                "success": False,
            },
                status=status.HTTP_402_PAYMENT_REQUIRED)
        
        Credits.objects.filter(pk=credit_entry.pk).update(
            credits_in_use=F('credits_in_use') + 1
        )

        token = Jobs.objects.create(credits=credit_entry).token

        return Response(
            {
                "message": MESSAGES['CREDITS_AVAILABLE'],
                "job_token": token,
                "success": True,
            },
                status=status.HTTP_200_OK)


class InititateBulkInferenceView(APIView):
    """
    View to check Bulk credits and allow
    inititation of inference
    """
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JWTAuthentication]
    authentication_classes = [JWTCookieAuthentication]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method handle Bulk inference initiation
        """
        user = request.user

        try:
            credit_entry = (
                BulkCredits.objects
                .filter(user=user)
                .select_for_update()
                .annotate(credits_available=F('credits') - F('credits_in_use'))
                .filter(credits_available__gt=0)
                .order_by('expires')
                .first()
            )
        except DatabaseError:
            return Response(
                {
                    "message": MESSAGES["SYSTEM_UNAVAILABLE"],
                    "success": False,
                },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        if not credit_entry:
            return Response(
            {
                "message": MESSAGES['CREDITS_UNAVAILABLE'],
                "success": False,
            },
                status=status.HTTP_402_PAYMENT_REQUIRED)
        
        BulkCredits.objects.filter(pk=credit_entry.pk).update(
            credits_in_use=F('credits_in_use') + 1
        )

        token = BulkJobs.objects.create(credits=credit_entry).token

        return Response(
            {
                "message": MESSAGES['CREDITS_AVAILABLE'],
                "job_token": token,
                "success": True,
            },
                status=status.HTTP_200_OK)


class WrapUpInferenceView(APIView):
    """
    View to wrap up inference cycle
    by deducting credits from the user
    """
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JWTAuthentication]
    authentication_classes = [JWTCookieAuthentication]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method to handle inference
        conclusion
        """
        serializer = WrapUpInferenceSerializer(
            data=request.data
        )

        if not serializer.is_valid():
            return Response(
                {
                    "error": serializer.errors,
                    "success": False,
                },
                    status=status.HTTP_400_BAD_REQUEST)

        job_token = serializer.validated_data['job_token']

        try:
            job = Jobs.objects.filter(token=job_token).values().first()

            if not job:
                return Response(
                    {
                        "message": MESSAGES["JOB_NOT_EXIST"],
                        "success": False,
                    },
                    status=status.HTTP_400_BAD_REQUEST)

            credit = Credits.objects.filter(pk=job["credits_id"]).select_for_update().values().first()

            if not credit or credit["credits"] <= 0:
                return Response(
                    {
                        "message": MESSAGES["CREDITS_NOT_DEDUCTED"],
                        "success": False,
                    },
                        status=status.HTTP_402_PAYMENT_REQUIRED)

            if credit["credits"] == 1:
                deleted, _ = Credits.objects.filter(pk=credits_id).delete()

            Credits.objects.filter(pk=job["credits_id"]).update(credits=F('credits')-1, credits_in_use=F('credits_in_use')-1)

            deleted, _ = Jobs.objects.filter(token=job_token).delete()
            
            return Response(
                {
                    "message": MESSAGES["CREDITS_DEDUCTED"],
                    "success": True,
                },
                    status=status.HTTP_200_OK)

        except DatabaseError as e:
            return Response(
                {
                    "error": str(e),
                    "success": False,
                },
                    status=status.HTTP_400_BAD_REQUEST)


class WrapUpBulkinferenceView(APIView):
    """
    View to warp up bulk inference cycle
    by deductiong credits from the user
    """
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JWTAuthentication]
    authentication_classes = [JWTCookieAuthentication]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method to handle Bulk inference
        conclusion
        """
        serializer = WrapUpInferenceSerializer(
            data = request.data
        )
 
        if not serializer.is_valid():
            return Response(
                {
                    "error": serializer.errors,
                    "success": False,
                },
                    status=status.HTTP_400_BAD_REQUEST)

        bulk_job_token = serializer.validated_data['job_token']

        try:
            job = BulkJobs.objects.filter(token=bulk_job_token).values().first()

            if not job:
                return Response(
                    {
                        "message": MESSAGES["JOB_NOT_EXIST"],
                        "success": False,
                    },
                    status=status.HTTP_400_BAD_REQUEST)

            credit = BulkCredits.objects.filter(pk=job['credits_id']).select_for_update().values().first()

            if not credit or credit["credits"] <= 0:
                return Response(
                    {
                        "message": MESSAGES["CREDITS_NOT_DEDUCTED"],
                        "success": False,
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED)

            if credit["credits"] == 1:
                deleted, _ = BulkCredits.objects.filter(pk=credits_id).delete()

            BulkCredits.objects.filter(pk=job["credits_id"]).update(credits=F('credits')-1, credits_in_use=F('credits_in_use')-1)

            deleted, _ = BulkJobs.objects.filter(token=bulk_job_token).delete()
            
            return Response(
                {
                    "message": MESSAGES["CREDITS_DEDUCTED"],
                    "success": True,
                },
                    status=status.HTTP_200_OK)

        except DatabaseError as e:
            return Response(
                {
                    "error": str(e),
                    "success": False,
                },
                    status=status.HTTP_400_BAD_REQUEST)

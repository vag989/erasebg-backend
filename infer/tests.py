import hmac
import hashlib
import base64
import time

from datetime import timedelta

from django.urls import reverse
from django.db.models import F
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APITestCase

from infer.models import Jobs, BulkJobs, APIJobs
from infer.utils.utils import tabulate_db_entries

from users.models import (
    CustomUser,
    Credits,
    BulkCredits,
    APICredits,
    APIKey,
    EmailVerificationTokens,
)

from erasebg.api.CONFIG import JOB_TOKEN_MAX_LENGTH
from erasebg.settings import CLOUDFLARE_WORKER_ID, CLOUDFLARE_WORKER_SHARED_SECRET


class InitiateInferenceWorkerViewTests(APITestCase):
    """
    Tests the infer app initiate inference end points
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )
        EmailVerificationTokens.objects.create(user=cls.user, verified=True)

        cls.num_credits = 100
        # cls.num_bulk_credits = 200
        # cls.num_api_credits = 100

        cls.credits = Credits.objects.create(user=cls.user, credits=cls.num_credits)
        # cls.bulk_credits = BulkCredits.objects.create(user=cls.user, credits=cls.num_bulk_credits)
        # cls.api_credits = APICredits.objects.create(user=cls.user, credits=cls.num_api_credits)

    @classmethod
    def setUp(cls):
        credentials = {
            "username": "testuser",
            "password": "Testuser123",
        }

        url = reverse("user-login")
        cls.login_res = cls.client.post(url, credentials, format="json")

    def get_worker_headers(self):
        id = CLOUDFLARE_WORKER_ID

        timestamp = str(int(time.time()))

        message = f"{id}:{timestamp}".encode("utf-8")
        key = CLOUDFLARE_WORKER_SHARED_SECRET.encode("utf-8")

        signature_bytes = hmac.new(key, message, hashlib.sha256).digest()
        signature = base64.b64encode(signature_bytes).decode("utf-8")

        return {
            "HTTP_X_AUTH_ID": id,
            "HTTP_X_AUTH_TIMESTAMP": timestamp,
            "HTTP_X_AUTH_SIGNATURE": signature,
        }

    def setup_multiple_credit_entries(
        self, num_credits: list[int], delete_existing=True
    ):
        """
        Adds multiple credit entries
        and sets up multiple entries test
        """
        if delete_existing:
            Credits.objects.all().delete()

        for credits in num_credits:
            Credits.objects.create(user=self.user, credits=credits)

    def setup_multiple_jobs_entries(self, num_jobs: int):
        """
        Adds mutliple job entries
        and sets up multiple jobs test
        """
        for _ in range(num_jobs):
            Jobs.objects.create(user=self.user)

    def test_initiate_inference_success(self):
        """
        Tests inittiate inference view
        """
        url = reverse("infer-initiate-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)
        self.assertIn("job_token", response.data)

        job = Jobs.objects.get(job_token=response.data["job_token"])
        self.assertIsNotNone(job)

    def test_initiate_inference_fail_authentication_no_access_token(self):
        """
        Tests inittiate inference view
        with no access_token in cookie
        """
        url = reverse("infer-initiate-bulk-inference")

        self.client.cookies.pop("access_token")
        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_wrong_token(self):
        """
        Tests initiate inference view
        with corrupted access_token in cookie
        """
        url = reverse("infer-initiate-inference")

        self.client.cookies["access_token"] = "corrupted_token"
        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_no_worker_headers(self):
        """
        Tests initiate inference view
        with no worker headers in cookie
        """
        url = reverse("infer-initiate-inference")

        response = self.client.post(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_wrong_worker_headers(self):
        """
        Tests initiate inference view
        with wrong worker headers in cookie
        """
        url = reverse("infer-initiate-inference")

        response = self.client.post(
            url,
            format="json",
            HTTP_X_AUTH_ID="wrong_id",
            HTTP_X_AUTH_TIMESTAMP="wrong_timestamp",
            HTTP_X_AUTH_SIGNATURE="wrong_signature",
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_zero_credits(self):
        """
        Tests initiate inference view with zero credits
        """
        self.credits.delete()

        url = reverse("infer-initiate-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_non_positive_credits(self):
        """
        Tests initiate inference view with zero credits
        """
        self.credits.credits = 0
        self.credits.save(update_fields=["credits"])

        url = reverse("infer-initiate-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_expired_credits(self):
        """
        Tests initiate inference view with expired credits
        """
        self.credits.expires = timezone.now() - timedelta(minutes=5)
        self.credits.save(update_fields=["expires"])

        url = reverse("infer-initiate-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_insufficient_tokens_with_active_jobs(self):
        """
        Tests initiate inference view with insufficient
        tokens and active jobs
        """
        self.credits.credits = 3
        self.credits.save(update_fields=["credits"])

        self.setup_multiple_jobs_entries(3)

        url = reverse("infer-initiate-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_success_with_expired_job(self):
        """
        Tests initiate inference view with expired
        job and a single credit
        """
        self.credits.credits = 1
        self.credits.save(update_fields=["credits"])

        Jobs.objects.create(
            user=self.user, expires=timezone.now() - timedelta(minutes=5)
        )

        url = reverse("infer-initiate-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

    def test_initiate_inference_multiple_credit_entries_success(self):
        """
        Tests initiate inference view multiple credit entries
        """
        credit_entries = [1, 2, 1]
        self.setup_multiple_credit_entries(credit_entries)

        url = reverse("infer-initiate-inference")

        for _ in range(sum(credit_entries)):
            response = self.client.post(url, format="json", **self.get_worker_headers())

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["success"], True)

    def test_initiate_inference_multiple_credit_entries_exhausted(self):
        """
        Tests initiate inference view multiple credit entries exhausted
        """
        credit_entries = [1, 2, 1]
        self.setup_multiple_credit_entries(credit_entries)

        url = reverse("infer-initiate-inference")

        for _ in range(sum(credit_entries)):
            response = self.client.post(url, format="json", **self.get_worker_headers())

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["success"], True)

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)


class InitiateBulkInferenceWorkerViewTests(APITestCase):
    """
    Tests the infer app initiate bulk inference end points
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )
        EmailVerificationTokens.objects.create(user=cls.user, verified=True)

        cls.num_bulk_credits = 200

        cls.bulk_credits = BulkCredits.objects.create(
            user=cls.user, credits=cls.num_bulk_credits
        )

    @classmethod
    def setUp(cls):
        credentials = {
            "username": "testuser",
            "password": "Testuser123",
        }

        url = reverse("user-login")
        cls.login_res = cls.client.post(url, credentials, format="json")

    def get_worker_headers(self):
        id = CLOUDFLARE_WORKER_ID

        timestamp = str(int(time.time()))

        message = f"{id}:{timestamp}".encode("utf-8")
        key = CLOUDFLARE_WORKER_SHARED_SECRET.encode("utf-8")

        signature_bytes = hmac.new(key, message, hashlib.sha256).digest()
        signature = base64.b64encode(signature_bytes).decode("utf-8")

        return {
            "HTTP_X_AUTH_ID": id,
            "HTTP_X_AUTH_TIMESTAMP": timestamp,
            "HTTP_X_AUTH_SIGNATURE": signature,
        }

    def setup_multiple_credit_entries(
        self, num_credits: list[int], delete_existing=True
    ):
        """
        Adds multiple credit entries
        and sets up multiple entries test
        """
        if delete_existing:
            BulkCredits.objects.all().delete()

        for credits in num_credits:
            BulkCredits.objects.create(user=self.user, credits=credits)

    def setup_multiple_jobs_entries(self, num_jobs: int):
        """
        Adds mutliple job entries
        and sets up multiple jobs test
        """
        for _ in range(num_jobs):
            BulkJobs.objects.create(user=self.user)

    def test_initiate_inference_success(self):
        """
        Tests inittiate inference view
        """
        url = reverse("infer-initiate-bulk-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)
        self.assertIn("job_token", response.data)

        job = BulkJobs.objects.get(job_token=response.data["job_token"])
        self.assertIsNotNone(job)

    def test_initiate_inference_fail_authentication_no_access_token(self):
        """
        Tests inittiate inference view
        with no access_token in cookie
        """
        url = reverse("infer-initiate-bulk-inference")

        self.client.cookies.pop("access_token")
        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_wrong_token(self):
        """
        Tests initiate inference view
        with corrupted access_token in cookie
        """
        url = reverse("infer-initiate-bulk-inference")

        self.client.cookies["access_token"] = "corrupted_token"
        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_no_worker_headers(self):
        """
        Tests initiate inference view
        with no worker headers in cookie
        """
        url = reverse("infer-initiate-bulk-inference")

        response = self.client.post(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_wrong_worker_headers(self):
        """
        Tests initiate inference view
        with wrong worker headers in cookie
        """
        url = reverse("infer-initiate-bulk-inference")

        response = self.client.post(
            url,
            format="json",
            HTTP_X_AUTH_ID="wrong_id",
            HTTP_X_AUTH_TIMESTAMP="wrong_timestamp",
            HTTP_X_AUTH_SIGNATURE="wrong_signature",
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_zero_credits(self):
        """
        Tests initiate inference view with zero credits
        """
        self.bulk_credits.delete()

        url = reverse("infer-initiate-bulk-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_non_positive_credits(self):
        """
        Tests initiate inference view with zero credits
        """
        self.bulk_credits.credits = 0
        self.bulk_credits.save(update_fields=["credits"])

        url = reverse("infer-initiate-bulk-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_expired_credits(self):
        """
        Tests initiate inference view with expired credits
        """
        self.bulk_credits.expires = timezone.now() - timedelta(minutes=5)
        self.bulk_credits.save(update_fields=["expires"])

        url = reverse("infer-initiate-bulk-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_insufficient_tokens_with_active_jobs(self):
        """
        Tests initiate inference view with insufficient
        tokens and active jobs
        """
        self.bulk_credits.credits = 3
        self.bulk_credits.save(update_fields=["credits"])

        self.setup_multiple_jobs_entries(3)

        url = reverse("infer-initiate-bulk-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_success_with_expired_job(self):
        """
        Tests initiate inference view with expired
        job and a single credit
        """
        self.bulk_credits.credits = 1
        self.bulk_credits.save(update_fields=["credits"])

        BulkJobs.objects.create(
            user=self.user, expires=timezone.now() - timedelta(minutes=5)
        )

        url = reverse("infer-initiate-bulk-inference")

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

    def test_initiate_inference_multiple_credit_entries_success(self):
        """
        Tests initiate inference view multiple credit entries
        """
        credit_entries = [1, 2, 1]
        self.setup_multiple_credit_entries(credit_entries)

        url = reverse("infer-initiate-bulk-inference")

        for _ in range(sum(credit_entries)):
            response = self.client.post(url, format="json", **self.get_worker_headers())

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["success"], True)

    def test_initiate_inference_multiple_credit_entries_exhausted(self):
        """
        Tests initiate inference view multiple credit entries exhausted
        """
        credit_entries = [1, 2, 1]
        self.setup_multiple_credit_entries(credit_entries)

        url = reverse("infer-initiate-bulk-inference")

        for _ in range(sum(credit_entries)):
            response = self.client.post(url, format="json", **self.get_worker_headers())

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["success"], True)

        response = self.client.post(url, format="json", **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)


class InitiateAPIInferenceWorkerViewTests(APITestCase):
    """
    Tests infer app initiate api inference end points
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )
        APIKey.objects.create(user=cls.user)
        EmailVerificationTokens.objects.create(user=cls.user, verified=True)

        cls.num_api_credits = 200

        cls.api_credits = APICredits.objects.create(
            user=cls.user, credits=cls.num_api_credits
        )

    def get_auth_headers(self):
        id = CLOUDFLARE_WORKER_ID

        timestamp = str(int(time.time()))

        message = f"{id}:{timestamp}".encode("utf-8")
        key = CLOUDFLARE_WORKER_SHARED_SECRET.encode("utf-8")

        signature_bytes = hmac.new(key, message, hashlib.sha256).digest()
        signature = base64.b64encode(signature_bytes).decode("utf-8")

        api_key = APIKey.objects.filter(user=self.user).first().key

        return {
            "HTTP_X_AUTH_ID": id,
            "HTTP_X_AUTH_TIMESTAMP": timestamp,
            "HTTP_X_AUTH_SIGNATURE": signature,
            "HTTP_AUTHORIZATION": "Key " + api_key,
        }

    def setup_multiple_credit_entries(
        self, num_credits: list[int], delete_existing=True
    ):
        """
        Adds multiple credit entries
        and sets up multiple entries test
        """
        if delete_existing:
            APICredits.objects.all().delete()

        for credits in num_credits:
            APICredits.objects.create(user=self.user, credits=credits)

    def setup_multiple_jobs_entries(self, num_jobs: int):
        """
        Adds mutliple job entries
        and sets up multiple jobs test
        """
        for _ in range(num_jobs):
            APIJobs.objects.create(user=self.user)

    def test_initiate_inference_success(self):
        """
        Tests inittiate inference view
        """
        url = reverse("infer-initiate-api-inference")

        response = self.client.post(url, format="json", **self.get_auth_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)
        self.assertIn("job_token", response.data)

        job = APIJobs.objects.get(job_token=response.data["job_token"])
        self.assertIsNotNone(job)

    def test_initiate_inference_fail_authentication_no_api_key(self):
        """
        Tests inittiate inference view
        with no access_token in cookie
        """
        url = reverse("infer-initiate-api-inference")

        headers = self.get_auth_headers()
        headers.pop("HTTP_AUTHORIZATION")

        response = self.client.post(url, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_wrong_api_key(self):
        """
        Tests initiate inference view
        with corrupted access_token in cookie
        """
        url = reverse("infer-initiate-api-inference")

        headers = self.get_auth_headers()
        headers["HTTP_AUTHORIZATION"] = "corrupt_key"

        response = self.client.post(url, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_no_worker_headers(self):
        """
        Tests initiate inference view
        with no worker headers in cookie
        """
        url = reverse("infer-initiate-api-inference")

        headers = {"HTTP_AUTHORIZATION": self.get_auth_headers()["HTTP_AUTHORIZATION"]}

        response = self.client.post(url, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_fail_authentication_invalid_worker_headers(self):
        """
        Tests initiate inference view
        with invalid worker headers in cookie
        """
        url = reverse("infer-initiate-api-inference")

        response = self.client.post(
            url,
            format="json",
            HTTP_X_AUTH_ID="wrong_id",
            HTTP_X_AUTH_TIMESTAMP="wrong_timestamp",
            HTTP_X_AUTH_SIGNATURE="wrong_signature",
            HTTP_AUTHORIZATION=self.get_auth_headers()["HTTP_AUTHORIZATION"],
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_zero_credits(self):
        """
        Tests initiate inference view with zero credits
        """
        self.api_credits.delete()

        url = reverse("infer-initiate-api-inference")

        response = self.client.post(url, format="json", **self.get_auth_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_non_positive_credits(self):
        """
        Tests initiate api inference view with zero credits
        """
        self.api_credits.credits = 0
        self.api_credits.save(update_fields=["credits"])

        url = reverse("infer-initiate-api-inference")

        response = self.client.post(url, format="json", **self.get_auth_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_expired_credits(self):
        """
        Tests initiate api inference view with expired credits
        """
        self.api_credits.expires = timezone.now() - timedelta(minutes=5)
        self.api_credits.save(update_fields=["expires"])

        url = reverse("infer-initiate-api-inference")

        response = self.client.post(url, format="json", **self.get_auth_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_insufficient_tokens_with_active_jobs(self):
        """
        Tests initiate inference view with insufficient
        tokens and active jobs
        """
        self.api_credits.credits = 3
        self.api_credits.save(update_fields=["credits"])

        self.setup_multiple_jobs_entries(3)

        url = reverse("infer-initiate-api-inference")

        response = self.client.post(url, format="json", **self.get_auth_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_success_with_expired_job(self):
        """
        Tests initiate inference view with expired
        job and a single credit
        """
        self.api_credits.credits = 1
        self.api_credits.save(update_fields=["credits"])

        APIJobs.objects.create(
            user=self.user, expires=timezone.now() - timedelta(minutes=5)
        )

        url = reverse("infer-initiate-api-inference")

        response = self.client.post(url, format="json", **self.get_auth_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

    def test_initiate_inference_multiple_credit_entries_success(self):
        """
        Tests initiate inference view multiple credit entries
        """
        credit_entries = [1, 2, 1]
        self.setup_multiple_credit_entries(credit_entries)

        url = reverse("infer-initiate-api-inference")

        for _ in range(sum(credit_entries)):
            response = self.client.post(url, format="json", **self.get_auth_headers())

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["success"], True)

    def test_initiate_inference_multiple_credit_entries_exhausted(self):
        """
        Tests initiate inference view multiple credit entries exhausted
        """
        credit_entries = [1, 2, 1]
        self.setup_multiple_credit_entries(credit_entries)

        url = reverse("infer-initiate-api-inference")

        for _ in range(sum(credit_entries)):
            response = self.client.post(url, format="json", **self.get_auth_headers())

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["success"], True)

        response = self.client.post(url, format="json", **self.get_auth_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)


class WrapUpInferenceWorkerViewTests(APITestCase):
    """
    Tests the infer app wrap up end points
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )

        cls.num_credits = 100

        cls.credits = Credits.objects.create(user=cls.user, credits=cls.num_credits)
        cls.job = Jobs.objects.create(user=cls.user)

        # print(tabulate_db_entries(Credits))
        # print(tabulate_db_entries(Jobs))
        # print(tabulate_db_entries(BulkCredits))
        # print(tabulate_db_entries(BulkJobs))

    def setup_multiple_credit_entries(
        self, num_credits: list[int], delete_existing=True
    ):
        """
        Adds multiple credit entries
        and sets up multiple entries test
        """
        if delete_existing:
            Credits.objects.all().delete()

        for credits in num_credits:
            Credits.objects.create(user=self.user, credits=credits)

    def get_worker_headers(self):
        id = CLOUDFLARE_WORKER_ID

        timestamp = str(int(time.time()))

        message = f"{id}:{timestamp}".encode("utf-8")
        key = CLOUDFLARE_WORKER_SHARED_SECRET.encode("utf-8")

        signature_bytes = hmac.new(key, message, hashlib.sha256).digest()
        signature = base64.b64encode(signature_bytes).decode("utf-8")

        return {
            "HTTP_X_AUTH_ID": id,
            "HTTP_X_AUTH_TIMESTAMP": timestamp,
            "HTTP_X_AUTH_SIGNATURE": signature,
        }

    def get_request_data(self):
        """
        Returns standard request data for wrapup inference worker
        """
        return {
            "job_token": self.job.job_token,
            "completion_status": "COMPLETE",
        }
    
    def test_wrapup_inference_missing_worker_auth_headers(self):
        """
        Tests wrapup of inference with missing
        worker auth headers
        """
        url = reverse("infer-wrapup-inference")

        data = self.get_request_data()

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrapup_inference_invalid_worker_auth_headers(self):
        """
        Tests wrapup of inference with invalid
        worker auth headers
        """
        url = reverse("infer-wrapup-inference")

        data = self.get_request_data()

        response = self.client.post(
            url,
            data,
            format="json",
            HTTP_X_AUTH_ID="wrong_id",
            HTTP_X_AUTH_TIMESTAMP="wrong_timestamp",
            HTTP_X_AUTH_SIGNATURE="wrong_signature",
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrapup_inference(self):
        """
        Tests wrapup of inference
        """
        url = reverse("infer-wrapup-inference")

        data = self.get_request_data()

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        job = Jobs.objects.get(job_token=self.job.job_token)
        self.assertTrue(job.completed_at < timezone.now())
        self.assertEqual(job.completion_status, "COMPLETE")

        credit_entry = Credits.objects.all().values().first()
        self.assertEqual(credit_entry["credits"], self.num_credits - 1)

    def test_wrapup_inference_missing_completion_status(self):
        """
        Tests wrapup of inference with missing completion status
        """
        url = reverse("infer-wrapup-inference")

        data = self.get_request_data()
        data.pop("completion_status")

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_missing_job_token(self):
        """
        Tests wrapup of inference with missing job token
        """
        url = reverse("infer-wrapup-inference")

        data = self.get_request_data()
        data.pop("job_token")

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_invalid_job_token(self):
        """
        Tests wrapup of inference with invalid job token
        """
        url = reverse("infer-wrapup-inference")

        data = self.get_request_data()
        data["job_token"] = "a" * JOB_TOKEN_MAX_LENGTH

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)


    def test_wrapup_inference_completed_job(self):
        """
        Tests wrapup of inference with compelted job
        """
        self.job.completed_at = timezone.now()
        self.job.save(update_fields=['completed_at'])

        url = reverse("infer-wrapup-inference")
        data = self.get_request_data()

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_zero_credits(self):
        """
        Tests wrapup of inference with no corresponding 
        credit entry in the table
        """
        self.credits.delete()

        url = reverse('infer-wrapup-inference')
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)


    def test_wrapup_inference_non_positive_credits(self):
        """
        Tests wrapup of inference with corresponding credits
        entry in the Credits table having 0 credits
        """
        self.credits.credits = 0
        self.credits.save(update_fields=['credits'])

        url = reverse('infer-wrapup-inference')
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_expired_credits(self):
        """
        Tests wrapup of inference no corresponding credits
        entry in the Credits table
        """
        self.credits.expires = timezone.now() - timedelta(minutes=5)
        self.credits.save(update_fields=['expires'])

        url = reverse('infer-wrapup-inference')
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_multiple_credit_entries(self):
        """
        Tests wrapup of inferene with multiple 
        credit entries
        """
        self.setup_multiple_credit_entries([100, 200, 300])

        url = reverse('infer-wrapup-inference')
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        # checks the first credit entry is deducted
        credit_entries = Credits.objects.all().order_by("expires")

        self.assertEqual(credit_entries[0].credits, 99)
        self.assertEqual(credit_entries[1].credits, 200)
        self.assertEqual(credit_entries[2].credits, 300)


class WrapUpBulkInferenceWorkerViewTests(APITestCase):
    """
    Tests the infer app wrap up bulk inference end points
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )

        cls.num_bulk_credits = 100

        cls.bulk_credits = BulkCredits.objects.create(user=cls.user, credits=cls.num_bulk_credits)
        cls.bulk_job = BulkJobs.objects.create(user=cls.user)


    def setup_multiple_credit_entries(
        self, num_credits: list[int], delete_existing=True
    ):
        """
        Adds multiple credit entries
        and sets up multiple entries test
        """
        if delete_existing:
            BulkCredits.objects.all().delete()

        for credits in num_credits:
            BulkCredits.objects.create(user=self.user, credits=credits)

    def get_worker_headers(self):
        id = CLOUDFLARE_WORKER_ID

        timestamp = str(int(time.time()))

        message = f"{id}:{timestamp}".encode("utf-8")
        key = CLOUDFLARE_WORKER_SHARED_SECRET.encode("utf-8")

        signature_bytes = hmac.new(key, message, hashlib.sha256).digest()
        signature = base64.b64encode(signature_bytes).decode("utf-8")

        return {
            "HTTP_X_AUTH_ID": id,
            "HTTP_X_AUTH_TIMESTAMP": timestamp,
            "HTTP_X_AUTH_SIGNATURE": signature,
        }

    def get_request_data(self):
        """
        Returns standard request data for wrapup inference worker
        """
        return {
            "job_token": self.bulk_job.job_token,
            "completion_status": "COMPLETE",
        }
    
    def test_wrapup_inference_missing_worker_auth_headers(self):
        """
        Tests wrapup of inference with missing
        worker auth headers
        """
        url = reverse("infer-wrapup-bulk-inference")

        data = self.get_request_data()

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrapup_inference_invalid_worker_auth_headers(self):
        """
        Tests wrapup of inference with invalid
        worker auth headers
        """
        url = reverse("infer-wrapup-bulk-inference")

        data = self.get_request_data()

        response = self.client.post(
            url,
            data,
            format="json",
            HTTP_X_AUTH_ID="wrong_id",
            HTTP_X_AUTH_TIMESTAMP="wrong_timestamp",
            HTTP_X_AUTH_SIGNATURE="wrong_signature",
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrapup_inference(self):
        """
        Tests wrapup of inference
        """
        url = reverse("infer-wrapup-bulk-inference")

        data = self.get_request_data()

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        job = BulkJobs.objects.get(job_token=self.bulk_job.job_token)
        self.assertTrue(job.completed_at < timezone.now())
        self.assertEqual(job.completion_status, "COMPLETE")

        credit_entry = BulkCredits.objects.all().values().first()
        self.assertEqual(credit_entry["credits"], self.num_bulk_credits - 1)

    def test_wrapup_inference_missing_completion_status(self):
        """
        Tests wrapup of inference with missing completion status
        """
        url = reverse("infer-wrapup-bulk-inference")

        data = self.get_request_data()
        data.pop("completion_status")

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_missing_job_token(self):
        """
        Tests wrapup of inference with missing job token
        """
        url = reverse("infer-wrapup-bulk-inference")

        data = self.get_request_data()
        data.pop("job_token")

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_invalid_job_token(self):
        """
        Tests wrapup of inference with invalid job token
        """
        url = reverse("infer-wrapup-bulk-inference")

        data = self.get_request_data()
        data["job_token"] = "a" * JOB_TOKEN_MAX_LENGTH

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)


    def test_wrapup_inference_completed_job(self):
        """
        Tests wrapup of inference with compelted job
        """
        self.bulk_job.completed_at = timezone.now()
        self.bulk_job.save(update_fields=['completed_at'])

        url = reverse("infer-wrapup-bulk-inference")
        data = self.get_request_data()

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_zero_credits(self):
        """
        Tests wrapup of inference with no corresponding 
        credit entry in the table
        """
        self.bulk_credits.delete()

        url = reverse("infer-wrapup-bulk-inference")
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)


    def test_wrapup_inference_non_positive_credits(self):
        """
        Tests wrapup of inference with corresponding credits
        entry in the Credits table having 0 credits
        """
        self.bulk_credits.credits = 0
        self.bulk_credits.save(update_fields=['credits'])

        url = reverse("infer-wrapup-bulk-inference")
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_expired_credits(self):
        """
        Tests wrapup of inference no corresponding credits
        entry in the Credits table
        """
        self.bulk_credits.expires = timezone.now() - timedelta(minutes=5)
        self.bulk_credits.save(update_fields=['expires'])

        url = reverse("infer-wrapup-bulk-inference")
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_multiple_credit_entries(self):
        """
        Tests wrapup of inferene with multiple 
        credit entries
        """
        self.setup_multiple_credit_entries([100, 200, 300])

        url = reverse("infer-wrapup-bulk-inference")
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        # checks the first credit entry is deducted
        credit_entries = BulkCredits.objects.all().order_by("expires")

        self.assertEqual(credit_entries[0].credits, 99)
        self.assertEqual(credit_entries[1].credits, 200)
        self.assertEqual(credit_entries[2].credits, 300)


class WrapUpAPIInferenceWorkerViewTests(APITestCase):
    """
    Tests the infer app wrap up api inference end points
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )

        cls.num_api_credits = 100

        cls.api_credits = APICredits.objects.create(user=cls.user, credits=cls.num_api_credits)
        cls.api_job = APIJobs.objects.create(user=cls.user)


    def setup_multiple_credit_entries(
        self, num_credits: list[int], delete_existing=True
    ):
        """
        Adds multiple credit entries
        and sets up multiple entries test
        """
        if delete_existing:
            APICredits.objects.all().delete()

        for credits in num_credits:
            APICredits.objects.create(user=self.user, credits=credits)

    def get_worker_headers(self):
        id = CLOUDFLARE_WORKER_ID

        timestamp = str(int(time.time()))

        message = f"{id}:{timestamp}".encode("utf-8")
        key = CLOUDFLARE_WORKER_SHARED_SECRET.encode("utf-8")

        signature_bytes = hmac.new(key, message, hashlib.sha256).digest()
        signature = base64.b64encode(signature_bytes).decode("utf-8")

        return {
            "HTTP_X_AUTH_ID": id,
            "HTTP_X_AUTH_TIMESTAMP": timestamp,
            "HTTP_X_AUTH_SIGNATURE": signature,
        }

    def get_request_data(self):
        """
        Returns standard request data for wrapup inference worker
        """
        return {
            "job_token": self.api_job.job_token,
            "completion_status": "COMPLETE",
        }
    
    def test_wrapup_inference_missing_worker_auth_headers(self):
        """
        Tests wrapup of inference with missing
        worker auth headers
        """
        url = reverse("infer-wrapup-api-inference")

        data = self.get_request_data()

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrapup_inference_invalid_worker_auth_headers(self):
        """
        Tests wrapup of inference with invalid
        worker auth headers
        """
        url = reverse("infer-wrapup-api-inference")

        data = self.get_request_data()

        response = self.client.post(
            url,
            data,
            format="json",
            HTTP_X_AUTH_ID="wrong_id",
            HTTP_X_AUTH_TIMESTAMP="wrong_timestamp",
            HTTP_X_AUTH_SIGNATURE="wrong_signature",
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrapup_inference(self):
        """
        Tests wrapup of inference
        """
        url = reverse("infer-wrapup-api-inference")

        data = self.get_request_data()

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        job = APIJobs.objects.get(job_token=self.api_job.job_token)
        self.assertTrue(job.completed_at < timezone.now())
        self.assertEqual(job.completion_status, "COMPLETE")

        credit_entry = APICredits.objects.all().values().first()
        self.assertEqual(credit_entry["credits"], self.num_api_credits - 1)

    def test_wrapup_inference_missing_completion_status(self):
        """
        Tests wrapup of inference with missing completion status
        """
        url = reverse("infer-wrapup-api-inference")

        data = self.get_request_data()
        data.pop("completion_status")

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_missing_job_token(self):
        """
        Tests wrapup of inference with missing job token
        """
        url = reverse("infer-wrapup-api-inference")

        data = self.get_request_data()
        data.pop("job_token")

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_invalid_job_token(self):
        """
        Tests wrapup of inference with invalid job token
        """
        url = reverse("infer-wrapup-api-inference")

        data = self.get_request_data()
        data["job_token"] = "a" * JOB_TOKEN_MAX_LENGTH

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_completed_job(self):
        """
        Tests wrapup of inference with compelted job
        """
        self.api_job.completed_at = timezone.now()
        self.api_job.save(update_fields=['completed_at'])

        url = reverse("infer-wrapup-api-inference")
        data = self.get_request_data()

        response = self.client.post(
            url, data, format="json", **self.get_worker_headers()
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_zero_credits(self):
        """
        Tests wrapup of inference with no corresponding 
        credit entry in the table
        """
        self.api_credits.delete()

        url = reverse("infer-wrapup-api-inference")
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)


    def test_wrapup_inference_non_positive_credits(self):
        """
        Tests wrapup of inference with corresponding credits
        entry in the Credits table having 0 credits
        """
        self.api_credits.credits = 0
        self.api_credits.save(update_fields=['credits'])

        url = reverse("infer-wrapup-api-inference")
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_expired_credits(self):
        """
        Tests wrapup of inference no corresponding credits
        entry in the Credits table
        """
        self.api_credits.expires = timezone.now() - timedelta(minutes=5)
        self.api_credits.save(update_fields=['expires'])

        url = reverse("infer-wrapup-api-inference")
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_multiple_credit_entries(self):
        """
        Tests wrapup of inferene with multiple 
        credit entries
        """
        self.setup_multiple_credit_entries([100, 200, 300])

        url = reverse("infer-wrapup-api-inference")
        data = self.get_request_data()

        response = self.client.post(url, data, format='json', **self.get_worker_headers())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        # checks the first credit entry is deducted
        credit_entries = APICredits.objects.all().order_by("expires")

        self.assertEqual(credit_entries[0].credits, 99)
        self.assertEqual(credit_entries[1].credits, 200)
        self.assertEqual(credit_entries[2].credits, 300)
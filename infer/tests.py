from django.urls import reverse
from django.db.models import F

from rest_framework import status
from rest_framework.test import APITestCase

from infer.models import Jobs, BulkJobs
from infer.utils.utils import tabulate_db_entries

from users.models import CustomUser, Credits, BulkCredits


class InferInitiateInferenceTests(APITestCase):           
    """
    Tests the infer app initiate inference end points
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username='user',
            email='user@example.com',
            password='user123'
        )

        cls.num_credits = 100
        cls.num_bulk_credits = 200

        cls.credits = Credits.objects.create(user=cls.user, credits=cls.num_credits)
        cls.bulk_credits = BulkCredits.objects.create(user=cls.user, credits=cls.num_bulk_credits)
    
    @classmethod
    def setUp(cls):
        credentials = {
            "username": "user",
            "password": "user123",
        }

        url = reverse('user-login')
        cls.login_res = cls.client.post(url, credentials, format='json')

    def setup_multiple_credit_entries(self, model):
        """
        Adds to more credit entries to the existing
        and sets of multiple entires test

        first entry  -> 1 credits
        second entry -> 1 credits
        third entry  -> 2 credits
        """
        credits_first_entry = 1
        credits_second_entry = 1
        credits_third_entry = 2

        model.objects.filter(user=self.user).update(
            credits = credits_first_entry
        )
        model.objects.create(user=self.user, credits=credits_second_entry)
        model.objects.create(user=self.user, credits=credits_third_entry)

        return credits_first_entry + credits_second_entry + credits_third_entry

    def test_initiate_inference(self):
        """
        Tests inittiate inference view
        """
        url = reverse('infer-initiate-inference')

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)
        self.assertIn('job_token', response.data)
        
        credits = Credits.objects.get(user=self.user)
        self.assertEqual(credits.credits, self.num_credits)
        self.assertEqual(credits.credits_in_use, 1)
        
        job = Jobs.objects.get(token=response.data['job_token'])
        self.assertIsNotNone(job)
        self.assertEqual(job.credits_id, credits.pk)


    def test_initiate_inference_fail_authentication_no_token(self):
        """
        Tests inittiate inference view 
        with no access_token in cookie
        """
        url = reverse('infer-initiate-bulk-inference')

        self.client.cookies.pop('access_token')
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_initiate_inference_fail_authentication_wrong_token(self):
        """
        Tests inittiate inference view 
        with corrupted access_token in cookie
        """
        url = reverse('infer-initiate-inference')

        self.client.cookies['access_token'] = 'corrupted_token'

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_inference_zero_credits(self):
        """
        Tests initiate inference view with zero credits
        """
        self.credits.delete()

        url = reverse('infer-initiate-inference')

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_inference_multiple_credit_entries(self):
        """
        Tests initiate inference view multiple credit entries
        """
        self.setup_multiple_credit_entries(Credits)
        credits_in_use_list = Credits.objects.values_list('credits_in_use', flat=True)

        url = reverse('infer-initiate-inference')

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)
        
        self.assertEqual(credits_in_use_list[0], 1)
        self.assertEqual(credits_in_use_list[1], 0)
        self.assertEqual(credits_in_use_list[2], 0)

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        self.assertEqual(credits_in_use_list[0], 1)
        self.assertEqual(credits_in_use_list[1], 1)
        self.assertEqual(credits_in_use_list[2], 0)

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        self.assertEqual(credits_in_use_list[0], 1)
        self.assertEqual(credits_in_use_list[1], 1)
        self.assertEqual(credits_in_use_list[2], 1)

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        self.assertEqual(credits_in_use_list[0], 1)
        self.assertEqual(credits_in_use_list[1], 1)
        self.assertEqual(credits_in_use_list[2], 2)
        
    def test_initiate_inference_multiple_credit_entries_exhausted(self):
        """
        Tests initiate inference view multiple credit entries exhausted
        """
        total_credits = self.setup_multiple_credit_entries(Credits)

        url = reverse('infer-initiate-inference')

        for i in range(total_credits):
            self.client.post(url, format='json')
        
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_bulk_inference(self):
        """
        Tests inittiate bulk inference view
        """
        url = reverse('infer-initiate-bulk-inference')

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)
        self.assertIn('job_token', response.data)
        
        credits = BulkCredits.objects.get(user=self.user)
        self.assertEqual(credits.credits, self.num_bulk_credits)
        self.assertEqual(credits.credits_in_use, 1)
        
        job = BulkJobs.objects.get(token=response.data['job_token'])
        self.assertIsNotNone(job)
        self.assertEqual(job.credits_id, credits.pk)

    def test_initiate_bulk_inference_fail_authentication_no_token(self):
        """
        Tests inittiate bulk inference view 
        with no access_token in cookie
        """
        url = reverse('infer-initiate-bulk-inference')

        self.client.cookies.pop('access_token')
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_initiate_bulk_inference_fail_authentication_wrong_token(self):
        """
        Tests initiate bulk inference view 
        with corrupted access_token in cookie
        """
        url = reverse('infer-initiate-bulk-inference')

        self.client.cookies['access_token'] = 'corrupted_token'

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_initiate_bulk_inference_zero_credits(self):
        """
        Tests initiate bulk inference view with zero credits
        """
        self.bulk_credits.delete()

        url = reverse('infer-initiate-bulk-inference')

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_initiate_bulk_inference_multiple_credit_entries(self):
        """
        Tests initiate bulk inference view multiple credit entries
        """
        self.setup_multiple_credit_entries(BulkCredits)
        credits_in_use_list = BulkCredits.objects.values_list('credits_in_use', flat=True)

        url = reverse('infer-initiate-bulk-inference')

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)
        
        self.assertEqual(credits_in_use_list[0], 1)
        self.assertEqual(credits_in_use_list[1], 0)
        self.assertEqual(credits_in_use_list[2], 0)

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        self.assertEqual(credits_in_use_list[0], 1)
        self.assertEqual(credits_in_use_list[1], 1)
        self.assertEqual(credits_in_use_list[2], 0)

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        self.assertEqual(credits_in_use_list[0], 1)
        self.assertEqual(credits_in_use_list[1], 1)
        self.assertEqual(credits_in_use_list[2], 1)

        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        self.assertEqual(credits_in_use_list[0], 1)
        self.assertEqual(credits_in_use_list[1], 1)
        self.assertEqual(credits_in_use_list[2], 2)

    def test_initiate_bulk_inference_multiple_credit_entries_exhausted(self):
        """
        Tests initiate bulk inference view multiple credit entries exhausted
        """
        total_credits = self.setup_multiple_credit_entries(BulkCredits)

        url = reverse('infer-initiate-bulk-inference')

        for i in range(total_credits):
            self.client.post(url, format='json')
        
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)


class InferWrapUpInferenceTests(APITestCase):
    """
    Tests the infer app wrap up end points
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username='user',
            email='user@example.com',
            password='user123'
        )

        cls.num_credits = 100
        cls.num_bulk_credits = 200

        cls.credits = Credits.objects.create(user=cls.user, credits=cls.num_credits, credits_in_use=1)
        cls.jobs = Jobs.objects.create(credits=cls.credits)

        cls.bulk_credits = BulkCredits.objects.create(user=cls.user, credits=cls.num_bulk_credits, credits_in_use=1)
        cls.bulk_jobs = BulkJobs.objects.create(credits=cls.bulk_credits)

        # print(tabulate_db_entries(Credits))
        # print(tabulate_db_entries(Jobs))
        # print(tabulate_db_entries(BulkCredits))
        # print(tabulate_db_entries(BulkJobs))
    
    @classmethod
    def setUp(cls):
        credentials = {
            "username": "user",
            "password": "user123",
        }

        url = reverse('user-login')
        cls.login_res = cls.client.post(url, credentials, format='json')

    def test_wrapup_inference(self):
        """
        Tests wrapup of inference
        """
        url = reverse('infer-wrapup-inference')

        data = {
            "job_token": self.jobs.token,
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        jobs = Jobs.objects.all().values_list()
        self.assertEqual(len(jobs), 0)

        credit_entry = Credits.objects.all().values().first()
        self.assertEqual(credit_entry["credits"], self.num_credits-1)
        self.assertEqual(credit_entry["credits_in_use"], 0)

    def test_wrapup_inference_no_token(self):
        """
        Tests wrapup of inference with no access_token
        """
        url = reverse('infer-wrapup-inference')
        data = {
            "job_token": self.jobs.token,
        }

        self.client.cookies.pop("access_token")

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_wrapup_inference_corrupted_token(self):
        """
        Tests wrapup of inference with corrupted access_token
        """
        url = reverse('infer-wrapup-inference')
        data = {
            "job_token": self.jobs.token,
        }

        self.client.cookies["access_token"] = 'corrupted_token'

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrapup_inference_no_job_token(self):
        """
        Tests wrapup of inference with no token
        """
        url = reverse('infer-wrapup-inference')

        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_incorrect_job_token(self):
        """
        Tests wrapup of inference with incorrect token
        """
        url = reverse('infer-wrapup-inference')
        data = {
            "job_token": "corrupted_token",
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_inference_zero_credits(self):
        """
        Tests wrapup of inference no corresponding credits
        entry in the Credits table
        """
        self.credits.credits = 0
        self.credits.credits_in_use = 0
        self.credits.save()

        url = reverse('infer-wrapup-inference')
        data = {
            "job_token": self.jobs.token,
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_bulk_inference(self):
        """
        Tests wrapup of bulk inference
        """
        url = reverse('infer-wrapup-bulk-inference')

        data = {
            "job_token": self.bulk_jobs.token,
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        bulkJobs = BulkJobs.objects.all().values_list()
        self.assertEqual(len(bulkJobs), 0)

        credit_entry = BulkCredits.objects.all().values().first()
        self.assertEqual(credit_entry["credits"], self.num_bulk_credits-1)
        self.assertEqual(credit_entry["credits_in_use"], 0)

    def test_wrapup_bulk_inference_no_token(self):
        """
        Tests wrapup of bulk inference with no access_token
        """
        url = reverse('infer-wrapup-bulk-inference')
        data = {
            "job_token": self.bulk_jobs.token,
        }

        self.client.cookies.pop("access_token")

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_wrapup_bulk_inference_corrupted_token(self):
        """
        Tests wrapup of bulk inference with corrupted access_token
        """
        url = reverse('infer-wrapup-bulk-inference')
        data = {
            "job_token": self.bulk_jobs.token,
        }

        self.client.cookies["access_token"] = 'corrupted_token'

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrapup_bulk_inference_no_job_token(self):
        """
        Tests wrapup of bulk inference with no token
        """
        url = reverse('infer-wrapup-bulk-inference')

        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_bulk_inference_incorrect_job_token(self):
        """
        Tests wrapup of inference with incorrect token
        """
        url = reverse('infer-wrapup-bulk-inference')
        data = {
            "job_token": "corrupted_token",
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_wrapup_bulk_inference_zero_credits(self):
        """
        Tests wrapup of bulk inference with zero credits to deduct
        """
        self.bulk_credits.credits = 0
        self.bulk_credits.credits_in_use = 0
        self.bulk_credits.save()

        url = reverse('infer-wrapup-bulk-inference')
        data = {
            "job_token": self.bulk_jobs.token,
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

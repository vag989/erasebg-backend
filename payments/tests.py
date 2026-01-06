from django.urls import reverse


from rest_framework.test import APITestCase
from rest_framework import status

from users.models import CustomUser, Credits, BulkCredits, APICredits

# Create your tests here.
class AddCreditsTests(APITestCase):
    """
    Tests cases for payments app
    """

    @classmethod
    def setUpTestData(cls):
        # Create regular user
        cls.regular_user = CustomUser.objects.create_user(
            username='regular_user',
            email='regular@example.com',
            password='testpass123'
        )
        
        # Create admin user
        cls.admin_user = CustomUser.objects.create_superuser(
            username='admin_user',
            email='admin@example.com',
            password='adminpass123'
        )


    def test_add_credits_admin(self):
        """
        Tests an admin can add credits to a user
        """
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 300,
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        credit_entry = Credits.objects.get(user=self.regular_user)
        self.assertEqual(credit_entry.credits, 300)
        self.assertEqual(credit_entry.credits_in_use, 0)

        bulk_credit_entry = BulkCredits.objects.filter(user=self.regular_user)
        self.assertFalse(bulk_credit_entry.exists())

        api_credit_entry = APICredits.objects.filter(user=self.regular_user)
        self.assertFalse(api_credit_entry.exists())


    def test_add_credits_regular_user(self):
        """
        Tests a regular user cannot add credits
        """
        self.client.force_authenticate(user=self.regular_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 100,
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
    def test_add_credits_bulk_credits_admin(self):
        """
        Tests an admin can add credits to a user
        """
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 500,
            "bulk_credits": 100,
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        credit_entry = Credits.objects.get(user=self.regular_user)
        self.assertEqual(credit_entry.credits, 500)
        self.assertEqual(credit_entry.credits_in_use, 0)

        bulk_credit_entry = BulkCredits.objects.filter(user=self.regular_user)[0]
        self.assertEqual(bulk_credit_entry.credits, 100)
        self.assertEqual(bulk_credit_entry.credits_in_use, 0)

        api_credit_entry = APICredits.objects.filter(user=self.regular_user)
        self.assertFalse(api_credit_entry.exists())

    def test_add_credits_bulk_credits_regular_user(self):
        """
        Tests a regular user cannot add credits
        """
        self.client.force_authenticate(user=self.regular_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 100,
            "bulk_credits": 100,
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_add_credits_api_credits_admin(self):
        """
        Tests an admin adds credits with api credits
        """
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 500,
            "api_credits": 100,
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        credit_entry = Credits.objects.get(user=self.regular_user)
        self.assertEqual(credit_entry.credits, 500)
        self.assertEqual(credit_entry.credits_in_use, 0)

        bulk_credit_entry = BulkCredits.objects.filter(user=self.regular_user)
        self.assertFalse(bulk_credit_entry.exists())

        api_credit_entry = APICredits.objects.filter(user=self.regular_user)[0]
        self.assertEqual(api_credit_entry.credits, 100)
        self.assertEqual(api_credit_entry.credits_in_use, 0)

    def test_add_credits_api_credits_regular_user(self):
        """
        Tests a regular user cannot add credits
        """
        self.client.force_authenticate(user=self.regular_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 100,
            "api_credits": 100,
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_add_credits_bulk_credits_api_credits_admin(self):
        """
        Tests a admin user can add all three types of credits
        """
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 500,
            "bulk_credits": 100,
            "api_credits": 100,
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        credit_entry = Credits.objects.get(user=self.regular_user)
        self.assertEqual(credit_entry.credits, 500)
        self.assertEqual(credit_entry.credits_in_use, 0)

        bulk_credit_entry = BulkCredits.objects.filter(user=self.regular_user)[0]
        self.assertEqual(bulk_credit_entry.credits, 100)
        self.assertEqual(bulk_credit_entry.credits_in_use, 0)

        api_credit_entry = APICredits.objects.filter(user=self.regular_user)[0]
        self.assertEqual(api_credit_entry.credits, 100)
        self.assertEqual(api_credit_entry.credits_in_use, 0)

    def test_add_credits_bulk_credits_api_credits_regular_user(self):
        """
        Tests a regular user cannot add credits
        """
        self.client.force_authenticate(user=self.regular_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 500,
            "bulk_credits": 100,
            "api_credits": 100,
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_add_multiple_credits_admin(self):
        """
        Test an amdin can add mutlipe credits to a user
        """

        self.client.force_authenticate(user=self.admin_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 500,
            "bulk_credits": 100,
            "api_credits": 100,
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        credit_entry = Credits.objects.filter(user=self.regular_user)[0]
        self.assertEqual(credit_entry.credits, 500)
        self.assertEqual(credit_entry.credits_in_use, 0)

        bulk_credit_entry = BulkCredits.objects.filter(user=self.regular_user)[0]
        self.assertEqual(bulk_credit_entry.credits, 100)
        self.assertEqual(bulk_credit_entry.credits_in_use, 0)

        api_credit_entry = APICredits.objects.filter(user=self.regular_user)[0]
        self.assertEqual(api_credit_entry.credits, 100)
        self.assertEqual(api_credit_entry.credits_in_use, 0)

        self.client.force_authenticate(user=self.admin_user)
        url = reverse('payments-add-credits')
        data = {
            "username": "regular_user",
            "num_credits": 300,
            "api_credits": 200,
        }

        response = self.client.post(url, data, format='json')

        credit_entries = Credits.objects.filter(user=self.regular_user)
        bulk_credit_entries = BulkCredits.objects.filter(user=self.regular_user)
        api_credit_entries = APICredits.objects.filter(user=self.regular_user)

        self.assertEqual(credit_entries.count(), 2)
        self.assertEqual(credit_entries[1].credits, 300)
        self.assertEqual(credit_entries[1].credits_in_use, 0)

        self.assertEqual(bulk_credit_entries.count(), 1)
        
        self.assertEqual(api_credit_entries.count(), 2)
        self.assertEqual(api_credit_entries[1].credits, 200)
        self.assertEqual(api_credit_entries[1].credits_in_use, 0)

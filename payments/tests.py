import base64

from django.urls import reverse


from rest_framework.test import APITestCase
from rest_framework import status

from users.models import CustomUser, Credits, BulkCredits

# Create your tests here.
class PaymetsTests(APITestCase):
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
        
    def test_add_bulk_credits_admin(self):
        """
        Tests an admin can add credits to a user
        """
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('payments-add-bulk-credits')
        data = {
            "username": "regular_user",
            "num_credits": 500,
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["success"], True)

        credit_entry = BulkCredits.objects.get(user=self.regular_user)
        self.assertEqual(credit_entry.credits, 100)
        self.assertEqual(credit_entry.credits_in_use, 0)    

    def test_add_bulk_credits_regular_user(self):
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

import io

from rest_framework.test import APITestCase
from rest_framework.parsers import JSONParser
from rest_framework import status
from django.urls import reverse


class UserTests(APITestCase):
    """
    User app tests
    """

    def signup(self):
        """
        Signup helper method
        """
        url = reverse('user-signup')
        data = {
            'username': 'testuser',
            'password': 'testpassword123',
            'email': 'testuser@example.com'
        }
        response = self.client.post(url, data, format='json')
        return response

    def login(self):
        """
        login helper method
        """
        url = reverse('user-login')
        data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }
        response = self.client.post(url, data, format='json')
        return response

    def test_signup(self):
        """
        Tests the signup functionality
        """
        response = self.signup()
        self.assertEqual(response.status_code,
                         status.HTTP_201_CREATED)

    def test_login(self):
        """
        Tests the login functionality
        """
        self.signup()
        response = self.login()
        self.assertEqual(response.status_code,
                         status.HTTP_200_OK)

    def test_token_refresh(self):
        """
        Tests the token refresh functionality
        """
        self.signup()
        response = self.login()

        url = reverse('user-token-refresh')
        stream = io.BytesIO(response.content)
        data = JSONParser().parse(stream)
        data.pop('access')

        response = self.client.post(url, data, format='json')
        self.assertContains(response, 'access',
                            status_code=status.HTTP_200_OK)

import io

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse


class UsersTests(APITestCase):
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

    def login(self, email=False, incorrect=False):
        """
        login helper method
        """
        url = reverse('user-login')
        data = {
            'password': 'testpassword123'
        }

        if incorrect:
            if email:
                data['email'] = 'testuser1@example.com'
            else:
                data['username'] = 'testuser1'
        else:
            if email:
                data['email'] = 'testuser@example.com'
            else:
                data['username'] = 'testuser'

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
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)

    def test_login_incorrect_username(self):
        """
        Tests login fail with incorrect username
        """
        self.signup()
        response = self.login(incorrect=True)

        self.assertEqual(response.status_code,
                         status.HTTP_400_BAD_REQUEST)
        self.assertNotIn('access_token', response.cookies)
        self.assertNotIn('refresh_token', response.cookies)

    def test_login_email(self):
        """
        Tests login with email
        """
        self.signup()
        response = self.login(email=True)

        self.assertEqual(response.status_code,
                         status.HTTP_200_OK)
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)

    def test_login_incorrect_email(self):
        """
        Tests login wit incorrect email
        """
        self.signup()
        response = self.login(email=True, incorrect=True)

        self.assertEqual(response.status_code,
                         status.HTTP_400_BAD_REQUEST)
        self.assertNotIn('access_token', response.cookies)
        self.assertNotIn('refresh_token', response.cookies)

    def test_token_refresh(self):
        """
        Tests the token refresh functionality
        """
        self.signup()
        _ = self.login()

        url = reverse('user-token-refresh')
        response = self.client.post(url, format='json')

        self.assertIn('access_token', response.cookies, "New access token not set in response")

    def test_token_refresh_fail(self):
        """
        Tests the token refresh fail when not including
        refresh token
        """
        self.signup()
        response = self.login()

        url = reverse('user-token-refresh')
        
        # remove refresh token from cookie
        self.client.cookies.pop('refresh_token')
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code,
                         status.HTTP_401_UNAUTHORIZED)

    def test_create_get_api_token(self):
        """
        Tests create or fetch API token 
        """
        self.signup()
        _ = self.login()

        url = reverse('user-api-token')
        response = self.client.post(url, format='json')

        self.assertIn('access_token', self.client.cookies)
        self.assertEqual(response.data.get('success'), True)
        self.assertIn('token', response.data)
    
    def test_create_get_api_token_fail(self):
        """
        Tests create or fetch API token
        fails when not authorized
        """
        self.signup()
        _ = self.login()

        url = reverse('user-api-token')

        self.client.cookies.pop('access_token')
        response = self.client.post(url, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIn('success', response.data)
        self.assertNotIn('token', response.data)

    def test_logout(self):
        """
        Tests cookies are cleared on logout
        """
        self.signup()
        _ = self.login()

        self.assertNotEqual(self.client.cookies['access_token']['expires'], 'Thu, 01 Jan 1970 00:00:00 GMT')
        self.assertNotEqual(self.client.cookies['refresh_token']['expires'], 'Thu, 01 Jan 1970 00:00:00 GMT')

        url = reverse('user-logout')
        response = self.client.post(url, format='json')

        self.assertEqual(self.client.cookies['access_token']['expires'], 'Thu, 01 Jan 1970 00:00:00 GMT')
        self.assertEqual(self.client.cookies['refresh_token']['expires'], 'Thu, 01 Jan 1970 00:00:00 GMT')
        self.assertEqual(response.data.get('success'), True)


# class UserCreditsTests(APITestCase):
#     """
#     Credits tests in user apps
#     """

#     @classmethod
#     def setUpTestData(cls):
        


    
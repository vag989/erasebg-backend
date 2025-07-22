import io

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from users.models import CustomUser, Credits, BulkCredits, APICredits

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


class UserCreditsTests(APITestCase):
    """
    Credits tests in user apps
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
        cls.num_api_credits = 300

        cls.credits = Credits.objects.create(user=cls.user, credits=cls.num_credits)
        cls.bulk_credits = BulkCredits.objects.create(user=cls.user, credits=cls.num_bulk_credits)
        cls.api_credits = APICredits.objects.create(user=cls.user,
                                                    credits=cls.num_api_credits)

    @classmethod
    def setUp(cls):
        cls.credentials = {
            "username": "user",
            "password": "user123",
        }

        url = reverse('user-login')
        cls.login_res = cls.client.post(url, cls.credentials, format='json')

    def setup_multiple_credit_entries(self, model):
        """
        Sets up multiple credit entries in given model
        """
        model.objects.all().delete()
        entries = [700, 800, 600]

        for entry in entries:
            model.objects.create(user=self.user, credits=entry)
        
        return entries

    def test_get_credits(self):
        """
        Tests fetching the credits for a user
        """
        url = reverse('user-credits')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["username"], self.credentials["username"])
        self.assertEqual(response.data[0]["credits"], self.num_credits)
        self.assertIn("created", response.data[0])
        self.assertIn("expires", response.data[0])

    def test_get_credits_no_auth(self):
        """
        Tests fetching credits for a user without 
        JWT access_token
        """
        url = reverse('user-credits')

        self.client.cookies.pop("access_token")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_credits_corrupt_token(self):
        """
        Tests fetching credits for a user with 
        corrupted JWT access_token
        """
        url = reverse('user-credits')

        self.client.cookies["access_token"] = "corrupted_token"

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_credits_wiht_no_credits(self):
        """
        Tests fetching credits with no credits 
        for a user
        """
        self.credits.delete()
        url = reverse('user-credits')

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_get_credits_multiple_credits(self):
        """
        Tests fetching credits with multiple 
        credit entries for a user
        """
        credits_entries = self.setup_multiple_credit_entries(Credits)

        url = reverse('user-credits')

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        for i, credit in enumerate(credits_entries):
            self.assertEqual(response.data[i]["username"], self.credentials["username"])
            self.assertEqual(response.data[i]["credits"], credit)
            self.assertIn("created", response.data[i])
            self.assertIn("expires", response.data[i])

    def test_get_bulk_credits(self):
        """
        Tests fetching the bulk credits for user
        """
        url = reverse('user-bulk-credits')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["username"], self.credentials["username"])
        self.assertEqual(response.data[0]["credits"], self.num_bulk_credits)
        self.assertIn("created", response.data[0])
        self.assertIn("expires", response.data[0])

    def test_get_bulk_credits_no_auth(self):
        """
        Tests fetching bulk credits for a user without 
        JWT access_token
        """
        url = reverse('user-bulk-credits')

        self.client.cookies.pop("access_token")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_bulk_credits_corrupt_token(self):
        """
        Tests fetching bulk credits for a user with 
        corrupted JWT access_token
        """
        url = reverse('user-bulk-credits')

        self.client.cookies["access_token"] = "corrupted_token"

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_bulk_credits_wiht_no_credits(self):
        """
        Tests fetching bulk credits with no credits 
        for a user
        """
        self.bulk_credits.delete()
        url = reverse('user-bulk-credits')

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_get_bulk_credits_multiple_credits(self):
        """
        Tests fetching bulk credits with multiple 
        credit entries for a user
        """
        credits_entries = self.setup_multiple_credit_entries(BulkCredits)

        url = reverse('user-bulk-credits')

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        for i, credit in enumerate(credits_entries):
            self.assertEqual(response.data[i]["username"], self.credentials["username"])
            self.assertEqual(response.data[i]["credits"], credit)
            self.assertIn("created", response.data[i])
            self.assertIn("expires", response.data[i])

    def test_get_api_credits(self):
        """
        Tests fetching the api credits for user
        """
        url = reverse('user-api-credits')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["username"], self.credentials["username"])
        self.assertEqual(response.data[0]["credits"], self.num_api_credits)
        self.assertIn("created", response.data[0])
        self.assertIn("expires", response.data[0])

    def test_get_api_credits_no_auth(self):
        """
        Tests fetching api credits for a user without 
        JWT access_token
        """
        url = reverse('user-api-credits')

        self.client.cookies.pop("access_token")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_api_credits_corrupt_token(self):
        """
        Tests fetching api credits for a user with 
        corrupted JWT access_token
        """
        url = reverse('user-api-credits')

        self.client.cookies["access_token"] = "corrupted_token"

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_api_credits_wiht_no_credits(self):
        """
        Tests fetching api credits with no credits 
        for a user
        """
        self.api_credits.delete()
        url = reverse('user-api-credits')

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success"], False)

    def test_get_api_credits_multiple_credits(self):
        """
        Tests fetching api credits with multiple 
        credit entries for a user
        """
        credits_entries = self.setup_multiple_credit_entries(APICredits)

        url = reverse('user-api-credits')

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        for i, credit in enumerate(credits_entries):
            self.assertEqual(response.data[i]["username"], self.credentials["username"])
            self.assertEqual(response.data[i]["credits"], credit)
            self.assertIn("created", response.data[i])
            self.assertIn("expires", response.data[i])

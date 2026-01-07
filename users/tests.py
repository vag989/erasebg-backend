from django.urls import reverse
from django.db.models import F
from django.utils import timezone

from datetime import timedelta

from rest_framework.test import APITestCase
from rest_framework import status

from users.models import (
    CustomUser,
    APIToken,
    Credits,
    BulkCredits,
    APICredits,
    EmailVerificationTokens,
    PasswordResetOTP,
)

from erasebg.api.CONFIG import MESSAGES, OTP_MAX_INCORRECT_ATTEMPTS


class UsersTests(APITestCase):
    """
    User app tests
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser",
            password="Testpassword123",
            email="testuser@example.com",
        )

        APIToken.objects.create(user=cls.user)
        EmailVerificationTokens.objects.create(user=cls.user, verified=True)

    @classmethod
    def setUp(cls):
        cls.credentials = {
            "username": "testuser",
            "password": "Testpassword123",
        }

        url = reverse("user-login")
        cls.login_res = cls.client.post(url, cls.credentials, format="json")

    def signup(self, data=None):
        """
        Signup helper method
        """
        url = reverse("user-signup")
        if not data:
            data = {
                "username": "testuser1",
                "password": "Testpassword123",
                "email": "testuser1@example.com",
            }
        response = self.client.post(url, data, format="json")
        return response

    def login(self, email=False, incorrect=False):
        """
        login helper method
        """
        url = reverse("user-login")
        data = {"password": "Testpassword123"}

        if incorrect:
            if email:
                data["email"] = "testuser2@example.com"
            else:
                data["username"] = "testuser2"
        else:
            if email:
                data["email"] = "testuser@example.com"
            else:
                data["username"] = "testuser"

        response = self.client.post(url, data, format="json")
        return response

    def test_signup(self):
        """
        Tests the signup functionality
        """
        response = self.signup()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_signup_duplicate_username(self):
        """
        Tests the singup functionality with
        duplicate username
        """
        data = {
            "username": "testuser",
            "password": "Testpassword123",
            "email": "testuser123@example.com",
        }

        response = self.signup(data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("success"), False)
        self.assertTrue("username" in response.data.get("errors"))
        self.assertFalse("email" in response.data.get("errors"))

    def test_signup_duplicate_email(self):
        """
        Tests the singup functionality with
        duplicate email
        """
        data = {
            "username": "testuser123",
            "password": "Testpassword123",
            "email": "testuser@example.com",
        }

        response = self.signup(data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("success"), False)
        self.assertFalse("username" in response.data.get("errors"))
        self.assertTrue("email" in response.data.get("errors"))

    def test_signup_duplicate_username_email(self):
        """
        Tests the signup functionality with
        duplicate username and email
        """
        data = {
            "username": "testuser",
            "password": "Testpassword123",
            "email": "testuser@example.com",
        }

        response = self.signup(data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("success"), False)
        self.assertTrue("username" in response.data.get("errors"))
        self.assertTrue("email" in response.data.get("errors"))

    def test_login(self):
        """
        Tests the login functionality
        """
        response = self.login()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", response.cookies)
        self.assertIn("refresh_token", response.cookies)

    def test_login_incorrect_username(self):
        """
        Tests login fail with incorrect username
        """
        response = self.login(incorrect=True)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("access_token", response.cookies)
        self.assertNotIn("refresh_token", response.cookies)

    def test_login_email(self):
        """
        Tests login with email
        """
        response = self.login(email=True)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", response.cookies)
        self.assertIn("refresh_token", response.cookies)

    def test_login_incorrect_email(self):
        """
        Tests login wit incorrect email
        """
        response = self.login(email=True, incorrect=True)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("access_token", response.cookies)
        self.assertNotIn("refresh_token", response.cookies)

    def test_token_refresh(self):
        """
        Tests the token refresh functionality
        """
        url = reverse("user-auth-token-refresh")
        response = self.client.post(url, format="json")

        self.assertIn(
            "access_token", response.cookies, "New access token not set in response"
        )

    def test_token_refresh_fail(self):
        """
        Tests the token refresh fail when not including
        refresh token
        """
        url = reverse("user-auth-token-refresh")

        # remove refresh token from cookie
        self.client.cookies.pop("refresh_token")
        response = self.client.post(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_get_api_token_not_exists(self):
        """
        Tests create or fetch API token does not exist
        """
        APIToken.objects.filter(user=self.user).delete()

        url = reverse('user-api-token')
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access_token', self.client.cookies)
        self.assertEqual(response.data.get('success'), True)
        self.assertIn('token', response.data)

    def test_create_get_api_token_exists(self):
        """
        Tests create or fetch API token
        alreay exists
        """
        url = reverse('user-api-token')
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', self.client.cookies)
        self.assertEqual(response.data.get('success'), True)
        self.assertIn('token', response.data)

    def test_create_get_api_token_no_auth_token(self):
        """
        Tests create or fetch API token
        fails when not authorized
        """
        url = reverse('user-api-token')

        self.client.cookies.pop('access_token')
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIn('success', response.data)
        self.assertNotIn('token', response.data)

    def test_create_get_api_token_corrupt_auth_token(self):
        """
        Tests create or fetch API token
        fails with corrupt auth token
        """
        url = reverse('user-api-token')

        self.client.cookies['access_token'] = 'corrupt_token'
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIn('success', response.data)
        self.assertNotIn('token', response.data)

    def test_update_details_success(self):
        """
        Tests updating user details
        """
        data = {
            "first_name": "test",
            "last_name": "user",
            "email": "testuser@example.com",
        }

        url = reverse("user-update-details")
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("success"))

    def test_update_details_no_auth_token(self):
        """
        Tests updating user details without
        JWT access_token
        """
        data = {
            "first_name": "test",
            "last_name": "user",
            "email": "testuser@example.com",
        }

        self.client.cookies.pop("access_token")

        url = reverse("user-update-details")
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_details_corrupted_auth_token(self):
        """
        Tests updating user details with
        corrupted JWT access_token
        """
        data = {
            "first_name": "test",
            "last_name": "user",
            "email": "testuser@example.com",
        }

        self.client.cookies["access_token"] = "corrupted_token"

        url = reverse("user-update-details")
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_details_invalid_first_name(self):
        """
        Tests updating user details with invalid first name
        """
        data = {
            "first_name": ("").join(["a"] * 151),
            "last_name": "user",
        }

        url = reverse("user-update-details")
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_details_invalid_last_name(self):
        """
        Tests updating user details with invalid last name
        """
        data = {
            "first_name": "test",
            "last_name": ("").join(["a"] * 151),
        }

        url = reverse("user-update-details")
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_details_non_unique_email(self):
        """
        Tests updating user details with non-uqnique email
        """
        self.signup()

        data = {
            "email": "testuser1@example.com",
        }

        url = reverse("user-update-details")
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("success"), False)
        self.assertEqual(
            response.data.get("message"), MESSAGES["USER_DETAILS_NON_UNIQUE_EMAIL"]
        )

    def test_fetch_user_details_no_name(self):
        """
        Tests fetching user details
        """
        url = reverse("user-details")
        response = self.client.get(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("username"), "testuser")
        self.assertEqual(response.data.get("first_name"), "")
        self.assertEqual(response.data.get("last_name"), "")
        self.assertEqual(response.data.get("email"), "testuser@example.com")
        self.assertIsNotNone(response.data.get("member_since"))

    def test_fetch_user_details_with_name(self):
        """
        Tests fetching user details
        """
        data = {
            "first_name": "test",
            "last_name": "user",
        }
        url = reverse("user-update-details")
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        url = reverse("user-details")
        response = self.client.get(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("username"), "testuser")
        self.assertEqual(response.data.get("first_name"), "test")
        self.assertEqual(response.data.get("last_name"), "user")
        self.assertEqual(response.data.get("email"), "testuser@example.com")
        self.assertIsNotNone(response.data.get("member_since"))

    def test_logout(self):
        """
        Tests cookies are cleared on logout
        """
        self.assertNotEqual(
            self.client.cookies["access_token"]["expires"],
            "Thu, 01 Jan 1970 00:00:00 GMT",
        )
        self.assertNotEqual(
            self.client.cookies["refresh_token"]["expires"],
            "Thu, 01 Jan 1970 00:00:00 GMT",
        )

        url = reverse("user-logout")
        response = self.client.post(url, format="json")

        self.assertEqual(
            self.client.cookies["access_token"]["expires"],
            "Thu, 01 Jan 1970 00:00:00 GMT",
        )
        self.assertEqual(
            self.client.cookies["refresh_token"]["expires"],
            "Thu, 01 Jan 1970 00:00:00 GMT",
        )
        self.assertEqual(response.data.get("success"), True)

    def test_logout_no_auth_token(self):
        self.client.cookies.pop("access_token")

        url = reverse("user-logout")
        response = self.client.post(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_corrupted_auth_token(self):
        self.client.cookies["access_token"] = "corrupted_token"

        url = reverse("user-logout")
        response = self.client.post(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class EmailVerificationTests(APITestCase):
    """
    Email verification tests in user apps
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )

        cls.email_verification_token = EmailVerificationTokens.objects.create(
            user=cls.user
        )

    def login(self):
        url = reverse("user-login")
        data = {
            "username": "testuser",
            "password": "Testuser123",
        }
        response = self.client.post(url, data, format="json")
        return response

    def verify_email(self):
        self.email_verification_token.verified = True
        self.email_verification_token.save(update_fields=["verified"])

    def test_login_without_verification(self):
        """
        Tests login without email verification
        """
        response = self.login()

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("success"), False)

    def test_login_with_verification(self):
        """
        Tests login with email verification
        """
        self.verify_email()
        response = self.login()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("success"), True)

    def test_verify_email_valid_token(self):
        """
        Tests email verification with valid token
        """
        url = reverse("user-email-verification")
        url += f"?email={self.user.email}&verification_token={self.email_verification_token.verification_token}"
        response = self.client.get(url, format="json")

        emailVerificationTokens = EmailVerificationTokens.objects.get(user=self.user)

        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertEqual(
            response.headers.get("Location"),
            "/html/email-verification-status?status=success",
        )
        self.assertEqual(emailVerificationTokens.verified, True)

    def test_verify_email_invalid_token(self):
        """
        Tests email verification with invalid token
        """
        url = reverse("user-email-verification")
        url += f"?email={self.user.email}&verification_token=invalidtoken"
        response = self.client.get(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertEqual(
            response.headers.get("Location"),
            "/html/email-verification-status?status=failure",
        )

    def test_verify_email_missing_email(self):
        """
        Tests email verification with missing email
        """
        url = reverse("user-email-verification")
        url += f"?verification_token={self.email_verification_token.verification_token}"
        response = self.client.get(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertEqual(
            response.headers.get("Location"),
            "/html/email-verification-status?status=failure",
        )

    def test_verify_email_missing_token(self):
        """
        Tests email verification with missing token
        """
        url = reverse("user-email-verification")
        url += f"?email={self.user.email}"
        response = self.client.get(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertEqual(
            response.headers.get("Location"),
            "/html/email-verification-status?status=failure",
        )

    def test_verify_email_missing_params(self):
        """
        Tests email verification with missing params
        """
        url = reverse("user-email-verification")
        response = self.client.get(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertEqual(
            response.headers.get("Location"),
            "/html/email-verification-status?status=failure",
        )


class ResendEmailVerificationTests(APITestCase):
    """
    Resend email verification tests in user apps
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )

        cls.email_verification_token = EmailVerificationTokens.objects.create(
            user=cls.user
        )

    def login(self):
        url = reverse("user-login")
        data = {
            "username": "testuser",
            "password": "Testuser123",
        }
        response = self.client.post(url, data, format="json")
        return response

    def verify_email(self):
        self.email_verification_token.verified = True
        self.email_verification_token.save(update_fields=["verified"])

    def test_resend_verification_email_exists_not_verified(self):
        """
        Tests resending verification email
        when not verified
        """
        url = reverse("user-resend-verification-email")
        data = {"email": "testuser@example.com"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("success"), True)

    def test_resend_verification_email_exists_verified(self):
        """
        Tests resending verification email
        when already verified
        """
        url = reverse("user-resend-verification-email")
        data = {"email": "testuser@example.com"}

        self.verify_email()
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("success"), False)

    def test_resend_verification_email_not_exists(self):
        """
        Tests resending verification email
        when email does not exist
        """
        url = reverse("user-resend-verification-email")
        data = {"email": "testusernotexists@example.com"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("success"), False)

    def test_resend_verification_wihtout_email(self):
        """
        Tests resending verification email
        without email
        """
        url = reverse("user-resend-verification-email")
        data = {}

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("success"), False)


class UserCreditsTests(APITestCase):
    """
    Credits tests in user apps
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_user(
            username="testuser", email="testuser@example.com", password="Testuser123"
        )

        APIToken.objects.create(user=cls.user)
        EmailVerificationTokens.objects.create(user=cls.user, verified=True)

        cls.num_credits = 100
        cls.num_bulk_credits = 200
        cls.num_api_credits = 300

        cls.credits = Credits.objects.create(user=cls.user, credits=cls.num_credits)
        cls.bulk_credits = BulkCredits.objects.create(
            user=cls.user, credits=cls.num_bulk_credits
        )
        cls.api_credits = APICredits.objects.create(
            user=cls.user, credits=cls.num_api_credits
        )

    @classmethod
    def setUp(cls):
        cls.credentials = {
            "username": "testuser",
            "password": "Testuser123",
        }

        url = reverse("user-login")
        cls.login_res = cls.client.post(url, cls.credentials, format="json")

    def setup_multiple_credit_entries(self, model, delete_existing=True):
        """
        Sets up multiple credit entries in given model
        """
        if delete_existing: model.objects.all().delete()
        entries = [700, 800, 600]

        for entry in entries:
            model.objects.create(user=self.user, credits=entry)

        return entries

    def test_get_credits(self):
        """
        Tests fetching the credits for a user
        """
        url = reverse("user-credits")
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
        url = reverse("user-credits")

        self.client.cookies.pop("access_token")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_credits_corrupt_token(self):
        """
        Tests fetching credits for a user with
        corrupted JWT access_token
        """
        url = reverse("user-credits")

        self.client.cookies["access_token"] = "corrupted_token"

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_credits_wiht_no_credits(self):
        """
        Tests fetching credits with no credits
        for a user
        """
        self.credits.delete()
        url = reverse("user-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_get_credits_multiple_credits(self):
        """
        Tests fetching credits with multiple
        credit entries for a user
        """
        credits_entries = self.setup_multiple_credit_entries(Credits)

        url = reverse("user-credits")

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
        url = reverse("user-bulk-credits")
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
        url = reverse("user-bulk-credits")

        self.client.cookies.pop("access_token")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_bulk_credits_corrupt_token(self):
        """
        Tests fetching bulk credits for a user with
        corrupted JWT access_token
        """
        url = reverse("user-bulk-credits")

        self.client.cookies["access_token"] = "corrupted_token"

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_bulk_credits_wiht_no_credits(self):
        """
        Tests fetching bulk credits with no credits
        for a user
        """
        self.bulk_credits.delete()
        url = reverse("user-bulk-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_get_bulk_credits_multiple_credits(self):
        """
        Tests fetching bulk credits with multiple
        credit entries for a user
        """
        credits_entries = self.setup_multiple_credit_entries(BulkCredits)

        url = reverse("user-bulk-credits")

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
        url = reverse("user-api-credits")
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
        url = reverse("user-api-credits")

        self.client.cookies.pop("access_token")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_api_credits_corrupt_token(self):
        """
        Tests fetching api credits for a user with
        corrupted JWT access_token
        """
        url = reverse("user-api-credits")

        self.client.cookies["access_token"] = "corrupted_token"

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_api_credits_wiht_no_credits(self):
        """
        Tests fetching api credits with no credits
        for a user
        """
        self.api_credits.delete()
        url = reverse("user-api-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_get_api_credits_multiple_credits(self):
        """
        Tests fetching api credits with multiple
        credit entries for a user
        """
        credits_entries = self.setup_multiple_credit_entries(APICredits)

        url = reverse("user-api-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        for i, credit in enumerate(credits_entries):
            self.assertEqual(response.data[i]["username"], self.credentials["username"])
            self.assertEqual(response.data[i]["credits"], credit)
            self.assertIn("created", response.data[i])
            self.assertIn("expires", response.data[i])

    def test_expired_credits_not_fetched(self):
        """
        Test that expired credits are not fetched
        """
        self.credits.expires = timezone.now() - timedelta(minutes=5)
        self.credits.save(update_fields=['expires'])

        url = reverse("user-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_expired_bulk_credits_not_fetched(self):
        """
        Test that expired bulk credits are not fetched
        """
        self.bulk_credits.expires = timezone.now() - timedelta(minutes=5)
        self.bulk_credits.save(update_fields=['expires'])

        url = reverse("user-bulk-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_expired_api_credits_not_fetched(self):
        """
        Test that expired api credits are not fetched
        """
        self.api_credits.expires = timezone.now() - timedelta(minutes=5)
        self.api_credits.save(update_fields=['expires'])

        url = reverse("user-api-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertEqual(response.data["success"], False)

    def test_expired_credits_with_multiple_credits(self):
        """
        Tests that expired credits are not fetched
        when having multiple entries
        """
        self.credits.expires = timezone.now() - timedelta(minutes=5)
        self.credits.save(update_fields=['expires'])

        credits_entries = self.setup_multiple_credit_entries(Credits, False)

        url = reverse("user-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), len(credits_entries))

        for i, credit in enumerate(credits_entries):
            self.assertEqual(response.data[i]["username"], self.credentials["username"])
            self.assertEqual(response.data[i]["credits"], credit)
            self.assertIn("created", response.data[i])
            self.assertIn("expires", response.data[i])

    def test_expired_bulk_credits_with_multiple_credits(self):
        """
        Tests that expired bulk credits are not fetched
        when having multiple entries
        """
        self.bulk_credits.expires = timezone.now() - timedelta(minutes=5)
        self.bulk_credits.save(update_fields=['expires'])

        credits_entries = self.setup_multiple_credit_entries(BulkCredits, False)

        url = reverse("user-bulk-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), len(credits_entries))

        for i, credit in enumerate(credits_entries):
            self.assertEqual(response.data[i]["username"], self.credentials["username"])
            self.assertEqual(response.data[i]["credits"], credit)
            self.assertIn("created", response.data[i])
            self.assertIn("expires", response.data[i])

    def test_expired_api_credits_with_multiple_credits(self):
        """
        Tests that expired api credits are not fetched
        when having multiple entries
        """
        self.api_credits.expires = timezone.now() - timedelta(minutes=5)
        self.api_credits.save(update_fields=['expires'])

        credits_entries = self.setup_multiple_credit_entries(APICredits, False)

        url = reverse("user-api-credits")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), len(credits_entries))

        for i, credit in enumerate(credits_entries):
            self.assertEqual(response.data[i]["username"], self.credentials["username"])
            self.assertEqual(response.data[i]["credits"], credit)
            self.assertIn("created", response.data[i])
            self.assertIn("expires", response.data[i])


class GetOTPViewTests(APITestCase):
    """
    Tests for GetOTP view in users app
    """

    @classmethod
    def setUpTestData(cls):
        cls.credentials = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "Testuser123",
        }
        cls.user = CustomUser.objects.create_user(
            username=cls.credentials["username"],
            email=cls.credentials["email"],
            password=cls.credentials["password"],
        )

        EmailVerificationTokens.objects.create(user=cls.user, verified=True)

    def create_otp_entry(self):
        return PasswordResetOTP.objects.create(self.user)

    def test_get_otp_success(self):
        """
        Tests otp fethcing success
        """
        url = reverse("user-reset-password-get-otp")

        data = {
            "email": self.credentials["email"],
        }

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("message"), MESSAGES["OTP_SENT"])
        self.assertEqual(response.data.get("email"), self.credentials["email"])
        self.assertEqual(response.data.get("success"), True)

    def test_get_otp_failure_no_email(self):
        """
        Tests otp fetching fails with no email
        """
        url = reverse("user-reset-password-get-otp")

        response = self.client.post(url, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue("errors" in response.data)
        self.assertEqual(response.data.get("success"), False)

    def test_get_otp_failure_incorrect_email(self):
        """
        Tests otp fetching with non-existent email
        """
        url = reverse("user-reset-password-get-otp")

        data = {"email": "user@example.com"}

        response = self.client.post(url, data=data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("message"), MESSAGES["EMAIL_NOT_FOUND"])
        self.assertEqual(response.data.get("success"), False)

    def test_get_otp_multiple_request_non_expired_otp(self):
        """
        Tests that the otp is same across requests if not expired
        """
        url = reverse("user-reset-password-get-otp")

        data = {
            "email": self.credentials["email"],
        }

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        otp_first = (
            PasswordResetOTP.objects.filter(user=self.user).values().first()["otp"]
        )

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        otp_second = (
            PasswordResetOTP.objects.filter(user=self.user).values().first()["otp"]
        )

        self.assertEqual(otp_first, otp_second)

    def test_get_otp_multiple_request_otp_max_incorrect(self):
        """
        Tests that the otp is different across requests
        when incorrect attempts count is reached
        """
        url = reverse("user-reset-password-get-otp")

        data = {
            "email": self.credentials["email"],
        }

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        otp_first = (
            PasswordResetOTP.objects.filter(user=self.user).values().first()["otp"]
        )

        PasswordResetOTP.objects.filter(user=self.user).select_for_update().update(
            incorrect_count=F("incorrect_count") + OTP_MAX_INCORRECT_ATTEMPTS
        )

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        otp_second = (
            PasswordResetOTP.objects.filter(user=self.user).values().first()["otp"]
        )

        self.assertNotEqual(otp_first, otp_second)

    def test_get_otp_multiple_request_otp_expired(self):
        """
        Tests that the otp is different across requests
        when otp is expired
        """
        url = reverse("user-reset-password-get-otp")

        data = {
            "email": self.credentials["email"],
        }

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        otp_first = (
            PasswordResetOTP.objects.filter(user=self.user).values().first()["otp"]
        )

        PasswordResetOTP.objects.filter(user=self.user).select_for_update().update(
            incorrect_count=F("incorrect_count") + OTP_MAX_INCORRECT_ATTEMPTS
        )

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        otp_second = (
            PasswordResetOTP.objects.filter(user=self.user).values().first()["otp"]
        )

        self.assertNotEqual(otp_first, otp_second)


class VerifyOTPViewTests(APITestCase):
    """
    Tests for VerifyOTP view in users app
    """

    @classmethod
    def setUpTestData(cls):
        cls.credentials = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "Testuser123",
        }
        cls.user = CustomUser.objects.create_user(
            username=cls.credentials["username"],
            email=cls.credentials["email"],
            password=cls.credentials["password"],
        )

        EmailVerificationTokens.objects.create(user=cls.user, verified=True)
        cls.otp_entry = PasswordResetOTP.objects.create(user=cls.user)

    def test_verify_otp_success(self):
        """
        Tests verify otp with correct otp
        """
        url = reverse("user-reset-password-verify-otp")

        data = {"email": self.credentials["email"], "otp": self.otp_entry.otp}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data.get("message"), MESSAGES["OTP_VERIFICATION_SUCCESSFUL"]
        )
        self.assertEqual(response.data.get("success"), True)

    def test_verify_otp_incorrect_otp(self):
        """
        Tests verify otp with incorrect otp
        """
        url = reverse("user-reset-password-verify-otp")

        data = {"email": self.credentials["email"], "otp": self.otp_entry.otp[::-1]}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("message"), MESSAGES["OTP_VERIFICATION_UNSUCCESSFUL"]
        )
        self.assertEqual(response.data.get("success"), False)

    def test_verify_otp_no_email(self):
        """
        Tests verify otp with no email in request
        """
        url = reverse("user-reset-password-verify-otp")

        data = {"otp": self.otp_entry.otp}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue("errors" in response.data)
        self.assertEqual(response.data.get("success"), False)

    def test_verify_otp_no_otp(self):
        """
        Tests verify otp with no otp in request
        """
        url = reverse("user-reset-password-verify-otp")

        data = {"email": self.credentials["email"]}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue("errors" in response.data)
        self.assertEqual(response.data.get("success"), False)

    def test_verify_otp_incorrect_email(self):
        """
        Tests verify otp with incorrect email
        """
        url = reverse("user-reset-password-verify-otp")

        data = {"email": "user@user.com", "otp": self.otp_entry.otp}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("message"), MESSAGES["EMAIL_NOT_FOUND"])
        self.assertEqual(response.data.get("success"), False)

    def test_verify_otp_no_entry(self):
        """
        Tests verify otp with no otp entry in db
        """
        url = reverse("user-reset-password-verify-otp")

        data = {"email": self.credentials["email"], "otp": self.otp_entry.otp}

        self.otp_entry.delete()
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("message"), MESSAGES["OTP_NOT_FOUND"])
        self.assertEqual(response.data.get("success"), False)

    def test_verify_otp_max_incorrect(self):
        """
        Tests verify otp with max incorrect attempts
        reached
        """
        url = reverse("user-reset-password-verify-otp")

        data = {"email": self.credentials["email"], "otp": self.otp_entry.otp}

        PasswordResetOTP.objects.filter(user=self.user).select_for_update().update(
            incorrect_count=OTP_MAX_INCORRECT_ATTEMPTS
        )
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("message"), MESSAGES["OTP_MAX_INCORRECT"])
        self.assertEqual(response.data.get("success"), False)


class UpdatePasswordViewTests(APITestCase):
    """
    Tests for update password view
    """

    @classmethod
    def setUpTestData(cls):
        cls.credentials = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "Testuser123",
        }
        cls.user = CustomUser.objects.create_user(
            username=cls.credentials["username"],
            email=cls.credentials["email"],
            password=cls.credentials["password"],
        )

        EmailVerificationTokens.objects.create(user=cls.user, verified=True)
        cls.otp_entry = PasswordResetOTP.objects.create(user=cls.user)

    @classmethod
    def setUp(cls):
        url = reverse("user-reset-password-verify-otp")
        data = {
            "email": cls.credentials["email"],
            "otp": cls.otp_entry.otp,
        }
        cls.client.post(url, data, format="json")

    def test_update_password_success(self):
        """
        Tests successful password update
        """
        url = reverse("user-reset-password-update-password")

        data = {"email": self.credentials["email"], "new_password": "Testusernew123"}

        old_password = self.user.password
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("success"))
        new_password = CustomUser.objects.get(username=self.user.username).password

        self.assertNotEqual(old_password, new_password)

    def test_update_password_no_password_update_token(self):
        """
        Tests update password with no password update token
        """
        url = reverse("user-reset-password-update-password")

        data = {"email": self.credentials["email"], "new_password": "Testusernew123"}

        self.client.cookies.pop("password_update_token")
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data.get("success"))

    def test_update_password_corrupted_password_update_token(self):
        """
        Tests update password with corrupted password update token
        """
        url = reverse("user-reset-password-update-password")

        data = {"email": self.credentials["email"], "new_password": "Testusernew123"}

        self.client.cookies["password_update_token"] = "corrupted_token"
        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data.get("success"))

    def test_update_password_no_email(self):
        """
        Tests update password with no email in request
        """
        url = reverse("user-reset-password-update-password")

        data = {
            "new_password": "Testusernew123",
        }

        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue("errors" in response.data)
        self.assertFalse(response.data.get("success"))

    def test_update_password_no_new_password(self):
        """
        Tests update password with no new password
        """
        url = reverse("user-reset-password-update-password")

        data = {
            "email": self.credentials["email"],
        }

        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue("errors" in response.data)
        self.assertFalse(response.data.get("success"))

    def test_update_password_email_not_found(self):
        """
        Tests udpate password with incorrect email
        """
        url = reverse("user-reset-password-update-password")

        data = {"email": "user@user.com", "new_password": "Testusernew123"}

        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("message"), MESSAGES["EMAIL_NOT_FOUND"])
        self.assertFalse(response.data.get("success"))

    def test_update_password_invalid_password_one(self):
        """
        Tests udpate password with invalid password
        """
        url = reverse("user-reset-password-update-password")

        data = {
            "email": self.credentials["email"],
            "new_password": "testusernew123",
        }

        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue("errors" in response.data)
        self.assertTrue("new_password" in response.data.get("errors"))
        self.assertFalse(response.data.get("success"))

    def test_update_password_invalid_password_two(self):
        """
        Tests udpate password with invalid password
        """
        url = reverse("user-reset-password-update-password")

        data = {
            "email": self.credentials["email"],
            "new_password": "TEST123",
        }

        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue("errors" in response.data)
        self.assertTrue("new_password" in response.data.get("errors"))
        self.assertFalse(response.data.get("success"))

    def test_update_password_invalid_password_three(self):
        """
        Tests udpate password with invalid password
        """
        url = reverse("user-reset-password-update-password")

        data = {
            "email": self.credentials["email"],
            "new_password": "testuserNew",
        }

        response = self.client.patch(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue("errors" in response.data)
        self.assertTrue("new_password" in response.data.get("errors"))
        self.assertFalse(response.data.get("success"))

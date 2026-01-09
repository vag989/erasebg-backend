# authentication.py
from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

from users.models import CustomUser, APIKey

class JWTCookieAuthentication(JWTAuthentication):
    """
    Class extending JWT Authenitcation to the requests 
    including them in cookies
    """
    def authenticate(self, request):
        # (1) Extract JWT from cookie
        access_token = request.COOKIES.get('access_token')

        if not access_token:
            return None  # No token, proceed to other auth classes

        # (2) Validate token (parent class handles decoding/verification)
        try:
            validated_token = self.get_validated_token(access_token)
            return self.get_user(validated_token), validated_token
        except Exception:
            raise AuthenticationFailed('Invalid or expired token',code='jwt_authentication_failed')
        

class APIKeyAuthentication(BaseAuthentication):
    """
    Class for API Key Authentication to authenticate
    API Key in Authorization Headers 
    """
    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")

        if not auth_header:
            return None

        try:
            return self.get_validated_key(auth_header)
        except Exception:
            raise AuthenticationFailed("Invalid or expired API Key", code='api_key_authentication_failed')

    def get_validated_key(self, auth_header):
        """
        params:
            auth_header - "KEY <API_KEY>"

        Return: 
            A two-tuple of user and validated key
        
        Raises: 
            AuthenticationFailedException
        """
        auth_header = auth_header.strip().split(' ')

        if len(auth_header) != 2:
            raise ValueError("Invalid authorization header format")

        if not (auth_header[0] == 'KEY' or auth_header[0] == 'Key' or auth_header[0] == 'key'):
            raise ValueError("Invalid authorization header format")
        
        api_key_entry = APIKey.objects.filter(key=auth_header[1]).first()

        if not api_key_entry:
            raise KeyError("API Key does not exist")
        
        user = CustomUser.objects.filter(pk=api_key_entry.user_id)

        # Assuming on_delete=Models.CASCADE is not 
        # set on APIKey model user one-to-one relation field and
        # user is deleted. Hence, invalid API Key.
        if not user:
            raise KeyError("API Key does not exist")
        
        return user, auth_header[1]



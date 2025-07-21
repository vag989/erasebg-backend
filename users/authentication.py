# authentication.py
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed


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

import time
import base64
import hmac
import hashlib
import random

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from users.authentication import JWTCookieAuthentication, APIKeyAuthentication

from erasebg.settings import CLOUDFLARE_WORKER_SHARED_SECRET


class WorkerHMACAuthentication(BaseAuthentication):
    """
    Auth class for verifying requests coming from Cloudflare Worker → Backend.
    """

    HEADER_ID = "HTTP_X_AUTH_ID"
    HEADER_TIMESTAMP = "HTTP_X_AUTH_TIMESTAMP"
    HEADER_SIGNATURE = "HTTP_X_AUTH_SIGNATURE"

    def authenticate(self, request):
        client_id = request.META.get(self.HEADER_ID)
        timestamp = request.META.get(self.HEADER_TIMESTAMP)
        signature = request.META.get(self.HEADER_SIGNATURE)

        # ----- 1. Check presence -----
        if not (client_id and timestamp and signature):
            raise AuthenticationFailed(
                "Incomplete authentication headers",
                code='authentication_failed'
            ) 

        # ----- 2. Validate timestamp -----
        try:
            ts = int(timestamp)
        except ValueError:
            raise AuthenticationFailed(
                "Invalid timestamp", 
                code="authentication_failed"
            )

        if abs(int(time.time()) - ts) > 300:  # 5 minute window
            raise AuthenticationFailed(
                "Timestamp out of allowed window", 
                code="authentication_failed"
            )

        # ----- 3. Validate signature -----
        secret = CLOUDFLARE_WORKER_SHARED_SECRET.encode()
        message = f"{client_id}:{timestamp}".encode()

        expected = hmac.new(secret, message, hashlib.sha256).digest()
        expected_b64 = base64.b64encode(expected).decode()

        # Constant-time comparison
        if not hmac.compare_digest(expected_b64, signature):
            raise AuthenticationFailed(
                "Invalid HMAC signature", 
                code="authentication_failed"
            )

        # ----- 4. Return a service user (no DB lookup needed) -----
        user = WorkerServiceUser(client_id)
        return (user, None)

    def authenticate_header(self, request):
        # Return a value so DRF returns 401 instead of 403
        return 'WorkerHMAC realm="api"'


class WorkerServiceUser:
    """
    Represents an internal service calling the API.
    No DB lookup, no permissions unless you assign them.
    """

    def __init__(self, service_name):
        """
        Note: make sure all attributes required like pk are 
        present especially when using user or scoped throttles
        """
        self.pk = random.randint(1, 1000000)  # Dummy primary key        
        self.username = service_name
        self.service_name = service_name
        self.is_authenticated = True
        self.is_anonymous = False

    def __str__(self):
        return f"ServiceUser({self.service_name})"


class WorkerHMACAndJWTCookieAuthentication(BaseAuthentication):
    """
    Requires BOTH:
    - valid Worker HMAC signature
    - Valid JWT Cookie for user identity
    """

    def authenticate(self, request):
        # 1. Authenticate Worker
        worker_auth = WorkerHMACAuthentication()
        
        worker_result = worker_auth.authenticate(request)

        if worker_result is None:
            raise AuthenticationFailed(
                "Missing or Invalid worker authentication",
                code="authentication_failed",
            )

        worker_user, _ = worker_result

        # 2. Authenticate User via JWT Cookie
        jwt_auth = JWTCookieAuthentication()

        user_result = jwt_auth.authenticate(request)
        if user_result is None:
            raise AuthenticationFailed(
                "Missing or Invalid user JWT authentication",
                code="jwt_authentication_failed",
            )

        user, _ = user_result

        request.worker = worker_user
        request.user = user

        return user_result

    def authenticate_header(self, request):
        # Return a value so DRF returns 401 instead of 403
        return 'WorkerAndJWT realm="api"'


class WorkerHMACAndAPIKeyAuthentication(BaseAuthentication):
    """
    Requires BOTH:
    - valid Worker HMAC signature
    - Valid API Token for user identity
    """

    def authenticate(self, request):
        # 1. Authenticate Worker
        worker_auth = WorkerHMACAuthentication()
        
        worker_result = worker_auth.authenticate(request)

        if worker_result is None:
            raise AuthenticationFailed(
                "Missing or Invalid worker authentication",
                code="authentication_failed",
            )

        worker_user, _ = worker_result
        
        # 2. Authenticate User via Token 
        token_auth = APIKeyAuthentication()

        user_result = token_auth.authenticate(request)
        if user_result is None:
            raise AuthenticationFailed(
                "Missing or Invalid user Token authentication",
                code="api_token_authentication_failed",
            )

        user, _ = user_result

        request.worker = worker_user
        request.user = user

        return user_result

    def authenticate_header(self, request):
        # Return a value so DRF returns 401 instead of 403
        return 'WorkerAndAPIKey realm="api"'
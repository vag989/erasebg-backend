from rest_framework.urls import path

from users.views.signup_view import UserSignUpView, ResendVerificationEmail, UserEmailVerificationView
from users.views.log_in_out_view import UserLoginView, UserLogoutView
from users.views.auth_tokens_views import JWTTokenRefreshView, APITokenView
from users.views.credits_views import CreditsView, BulkCreditsView, APICreditsView
# from users.views import UserLoginView, TokenRefreshView, GenerateAPITokenView
from users.views.user_details import UserDetailsView, UpdateDetailsView
from users.views.reset_password import GetOTPView, VerifyOTPView, UpdatePasswordView

from users.views.helpers.verificaiton_token_otp_views import GetOTPHelperView, GetVerificationLinkHelperView

from erasebg.settings import DEBUG

urlpatterns = [
    path('signup/', UserSignUpView.as_view(), name='user-signup'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('auth-token/refresh/', JWTTokenRefreshView.as_view(), name='user-auth-token-refresh'),
    path('get-api-token/', APITokenView.as_view(), name='user-api-token'),
    path('details/', UserDetailsView.as_view(), name='user-details'),
    path('update-details/', UpdateDetailsView.as_view(), name='user-update-details'),
    path('get-credits/', CreditsView.as_view(), name='user-credits'),
    path('get-bulk-credits/', BulkCreditsView.as_view(), name='user-bulk-credits'),
    path('get-api-credits/', APICreditsView.as_view(), name='user-api-credits'),
    path('reset-password/get-otp/', GetOTPView.as_view(), name='user-reset-password-get-otp'),
    path('reset-password/verify-otp/', VerifyOTPView.as_view(), name='user-reset-password-verify-otp'),
    path('reset-password/update-password/', UpdatePasswordView.as_view(), name='user-reset-password-update-password'),
    path('resend-verification-email/', ResendVerificationEmail.as_view(), name='user-resend-verification-email'),
    path('verify-email/', UserEmailVerificationView.as_view(), name='user-email-verification'),
    path('logout/', UserLogoutView.as_view(), name='user-logout'),
]

if DEBUG:
    urlpatterns += [
        path('helpers/email-verification-token/', GetVerificationLinkHelperView.as_view(), name='user-email-verification-token'),
        path('helpers/password-reset-otp/', GetOTPHelperView.as_view(), name='user-get-otp')
    ] 
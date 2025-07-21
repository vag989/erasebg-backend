from rest_framework.urls import path

# from rest_framework_simplejwt.views import TokenRefreshView

from users.views.signup_view import UserSignUpView
from users.views.log_in_out_view import UserLoginView, UserLogoutView
from users.views.tokens_views import TokenRefreshView, APITokenView
from users.views.credits_views import CreditsView, BulkCreditsView, APICreditsView
# from users.views import UserLoginView, TokenRefreshView, GenerateAPITokenView

urlpatterns = [
    path('signup/', UserSignUpView.as_view(), name='user-signup'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='user-token-refresh'),
    path('get-api-token/', APITokenView.as_view(), name='user-api-token'),
    path('get-credits/', CreditsView.as_view(), name='user-credits'),
    path('get-bulk-credits/', BulkCreditsView.as_view(), name='user-bulk-credits'),
    path('get-api-credits', APICreditsView.as_view(), name='user-api-credits'),
    path('logout/', UserLogoutView.as_view(), name='user-logout'),
]

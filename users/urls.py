from rest_framework.urls import path

# from rest_framework_simplejwt.views import TokenRefreshView

from users.views import UserSignUpView, UserLoginView, TokenRefreshView

urlpatterns = [
    path('signup/', UserSignUpView.as_view(), name='user-signup'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='user-token-refresh'),
]

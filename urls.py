from django.urls import path
from .views import (
    RegisterOrLoginAPIView, RegisterAPIView, RegisterVerifyPhoneAPIView, RegisterVerifyEmailAPIView,
    LoginPasswordAPIView, LoginPasswordResetRequestAPIView, LoginPasswordResetConfirmAPIView,
    LoginSetNewPasswordAPIView, ChangePasswordAPIView, LoginEmailOTPAPIView, LoginVerifyEmailAPIView,
    LoginVerifyPhoneAPIView, LoginPhoneOTPAPIView, SetNewPasswordAPIView, PasswordResetRequestAPIView,
    PasswordResetConfirmAPIView, NewEmailAPIView, NewEmailVerifyAPIView, UserAccountInformationAPIView,
    NewPhoneAPIView, NewPhoneVerifyAPIView,
)

app_name = 'accounts'

urlpatterns = [
    path('register-or-login/', RegisterOrLoginAPIView.as_view(), name='register-or-login'),
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('register/verify-email/', RegisterVerifyEmailAPIView.as_view(), name='register-verify-email'),
    path('register/verify-phone/', RegisterVerifyPhoneAPIView.as_view(), name='register-verify-phone'),
    path('login-password/', LoginPasswordAPIView.as_view(), name='login-password'),
    path('login-email-otp/', LoginEmailOTPAPIView.as_view(), name='login-email-otp'),
    path('login/verify-email/', LoginVerifyEmailAPIView.as_view(), name='login-verify-email'),
    path('login-phone-otp/', LoginPhoneOTPAPIView.as_view(), name='login-phone-otp'),
    path('login/verify-phone/', LoginVerifyPhoneAPIView.as_view(), name='login-verify-phone'),
    path('login/password-reset/', LoginPasswordResetRequestAPIView.as_view(), name='login-password-reset'),
    path(
        'login/password-reset-confirm/<uidb64>/<token>/', LoginPasswordResetConfirmAPIView.as_view(),
        name='login-password-rest-confirm'
    ),
    path('login/set-new-password/', SetNewPasswordAPIView.as_view(), name='set-new-password'),
    path('password-reset/', PasswordResetRequestAPIView.as_view(), name='password-reset'),
    path(
        'password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmAPIView.as_view(),
        name='login-password-rest-confirm'
    ),
    path('set-new-password/', LoginSetNewPasswordAPIView.as_view(), name='set-new-password'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change-password'),
    path('new-email/', NewEmailAPIView.as_view(), name='new-email'),
    path('new-email-verify/', NewEmailVerifyAPIView.as_view(), name='new-email-verify'),
    path('new-phone/', NewPhoneAPIView.as_view(), name='new-phone'),
    path('new-phone-verify/', NewPhoneVerifyAPIView.as_view(), name='new-phone-verify'),
    path('user-account-information/', UserAccountInformationAPIView.as_view(), name='user-account-information'),
]

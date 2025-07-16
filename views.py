from .models import User, Phone, Email
from .serializers import (
    RegisterOrLoginSerializer, RegisterSerializer, RegisterVerifyEmailSerializer, RegisterVerifyPhoneSerializer,
    LoginPasswordSerializer, LoginPasswordResetRequestSerializer,
    LoginSetNewPasswordSerializer, ChangePasswordSerializers, NewEmailSerializer, NewPhoneSerializer,
    UserAccountInformationSerializer, LoginVerifyEmailSerializer,
    LoginVerifyPhoneSerializer, LoginPhoneOTPSerializer, LoginEmailOTPSerializer, PasswordResetRequestSerializer,
    SetNewPasswordSerializer, NewEmailVerifySerializer, NewPhoneVerifySerializer
)
from django.shortcuts import redirect
from django.utils.translation import gettext as _
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from rest_framework import status
from rest_framework.generics import GenericAPIView, UpdateAPIView, RetrieveUpdateAPIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from email_validator.exceptions_types import EmailNotValidError
import random
import datetime
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from smtplib import SMTPException


# region register or login

class RegisterOrLoginAPIView(GenericAPIView):
    serializer_class = RegisterOrLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        user = validated_data.get('user')
        email_or_phone = validated_data.get('email_or_phone')
        request.session['email_or_phone'] = email_or_phone

        if user:
            return redirect(reverse('accounts:login-password'))

        return redirect(reverse('accounts:register'))

# endregion


# region register

class RegisterAPIView(GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        email_or_phone = request.session.get('email_or_phone')
        password = validated_data['password']

        request.session['email_or_phone'] = email_or_phone
        request.session['password'] = password

        if '@' in email_or_phone:
            request.session['user_email'] = email_or_phone
            user = User.objects.create_user(username=email_or_phone, password=password)
            user.save()
            email_instance = Email.objects.create(user=user, email=email_or_phone)
            email_instance.generate_security_code()
            email_instance.send_confirmation()
            email_instance.save()
            return redirect('accounts:register-verify-email')
        else:
            request.session['user_phone'] = email_or_phone
            user = User.objects.create_user(username=email_or_phone, password=password)
            user.save()
            phone_instance = Phone.objects.create(user=user, phone=email_or_phone)
            phone_instance.generate_security_code()
            phone_instance.send_confirmation()
            phone_instance.save()
            return redirect('accounts:register-verify-phone')


class RegisterVerifyEmailAPIView(GenericAPIView):
    serializer_class = RegisterVerifyEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})

        if serializer.is_valid():
            message = {'detail': _('ایمیل با موفقیت تأیید شد.')}
            return Response(message, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterVerifyPhoneAPIView(GenericAPIView):
    serializer_class = RegisterVerifyPhoneSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})

        if serializer.is_valid():
            message = {'detail': _('شماره تلفن با موفقیت تأیید شد.')}
            return Response(message, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# endregion


# region login with password

class LoginPasswordAPIView(GenericAPIView):
    serializer_class = LoginPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email_or_phone = request.session.get('email_or_phone')
        password = request.data.get('password')

        try:
            user = User.objects.get(email_address__email=email_or_phone)
        except (EmailNotValidError, User.DoesNotExist):
            try:
                user = User.objects.get(phone_number__phone=email_or_phone)
            except User.DoesNotExist:
                raise AuthenticationFailed(_('user not found.'))

        if not user.is_verified:
            raise AuthenticationFailed(_('user is not verified.'))

        if user.check_password(password):
            response_data = {
                "username": user.username,
                "access_token": str(AccessToken.for_user(user)),
                "refresh_token": str(RefreshToken.for_user(user)),
            }
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            raise AuthenticationFailed(_('wrong password.'))

# endregion


# region login with otp

class LoginEmailOTPAPIView(GenericAPIView):
    serializer_class = LoginEmailOTPSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        email = validated_data['email']
        request.session['email'] = email
        email_instance = Email.objects.get(email=email)
        email_instance.generate_security_code()
        email_instance.send_confirmation()
        email_instance.save()
        return redirect('accounts:login-verify-email')


class LoginVerifyEmailAPIView(GenericAPIView):
    serializer_class = LoginVerifyEmailSerializer

    def post(self, request):
        email = request.session.get('email')
        user = User.objects.get(email_address__email=email)
        serializer = self.serializer_class(data=request.data, context={'request': request})

        if serializer.is_valid():
            response_data = {
                "username": user.username,
                "access_token": str(AccessToken.for_user(user)),
                "refresh_token": str(RefreshToken.for_user(user)),
            }
            return Response(response_data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginPhoneOTPAPIView(GenericAPIView):
    serializer_class = LoginPhoneOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        phone = validated_data['phone']
        request.session['phone'] = phone
        phone_instance = Phone.objects.get(phone=phone)
        phone_instance.generate_security_code()
        phone_instance.send_confirmation()
        phone_instance.save()
        return redirect('accounts:login-verify-phone')


class LoginVerifyPhoneAPIView(GenericAPIView):
    serializer_class = LoginVerifyPhoneSerializer

    def post(self, request):
        phone = request.session.get('phone')
        user = User.objects.get(phone_number__phone=phone)
        serializer = self.serializer_class(data=request.data, context={'request': request})

        if serializer.is_valid():
            response_data = {
                "username": user.username,
                "access_token": str(AccessToken.for_user(user)),
                "refresh_token": str(RefreshToken.for_user(user)),
            }
            return Response(response_data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# endregion


# region login with Google

class LoginGoogleAPIView(GenericAPIView):
    pass

# endregion


# region login password reset

class LoginPasswordResetRequestAPIView(GenericAPIView):
    serializer_class = LoginPasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(
            {'message': 'پیامی حاوی لینک تغییر رمز عبور به آدرس ایمیلتان ارسال شد.'}, status=status.HTTP_200_OK
        )


class LoginPasswordResetConfirmAPIView(GenericAPIView):

    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {'message': 'توکن نامعتبر است یا منقضی شده است.'}, status=status.HTTP_401_UNAUTHORIZED
                )
            return Response({'success': True, 'message': 'اعتبارنامه معتبر است.', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'message': 'توکن نامعتبر است یا منقضی شده است.'}, status=status.HTTP_401_UNAUTHORIZED)


class LoginSetNewPasswordAPIView(GenericAPIView):
    serializer_class = LoginSetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user, validated_data = serializer.validated_data

        authenticated_user = authenticate(request=request, username=user.username, password=validated_data['password'])
        if authenticated_user:
            access_token = AccessToken.for_user(authenticated_user)
            refresh_token = RefreshToken.for_user(authenticated_user)

            response_data = {
                'success': True,
                'message': "بازنشانی رمز عبور با موفقیت انجام شد.",
                "username": authenticated_user.username,
                "access_token": str(access_token),
                "refresh_token": str(refresh_token),
            }
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            return Response(
                {'message': 'کاربر یافت نشد یا رمز عبور نامعتبر است.'}, status=status.HTTP_400_BAD_REQUEST
            )

# endregion


# region change password

class ChangePasswordAPIView(UpdateAPIView):
    serializer_class = ChangePasswordSerializers
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def perform_update(self, serializer):
        serializer.save()

# endregion


# region password reset

class PasswordResetRequestAPIView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(
            {'message': 'پیامی حاوی لینک تغییر رمز عبور به آدرس ایمیلتان ارسال شد.'}, status=status.HTTP_200_OK
        )


class PasswordResetConfirmAPIView(GenericAPIView):

    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {'message': 'توکن نامعتبر است یا منقضی شده است.'}, status=status.HTTP_401_UNAUTHORIZED
                )
            return Response({'success': True, 'message': 'اعتبارنامه معتبر است.', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'message': 'توکن نامعتبر است یا منقضی شده است.'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {'success': True, 'message': "بازنشانی رمز عبور با موفقیت انجام شد."}, status=status.HTTP_200_OK
        )

# endregion


# region new email

class NewEmailAPIView(GenericAPIView):
    serializer_class = NewEmailSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validate_data = serializer.validated_data
        email = validate_data['email']
        request.session['email'] = email
        user = request.user
        security_code = random.randint(100000, 999999)
        request.session['generated_security_code'] = security_code
        sent_datetime = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        request.session['sent_datetime'] = sent_datetime
        expiration_date = timezone.now() + datetime.timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES)
        expiration_date_str = expiration_date.strftime("%Y-%m-%d %H:%M:%S")
        request.session['expiration_date'] = expiration_date_str
        subject = _('تایید ایمیل')
        message = f"""
        {settings.EMAIL_SUBJECT_PREFIX} :
        سلام {user.username}

        کد تأیید ایمیل شما {security_code} است.

        این کد {settings.TOKEN_EXPIRE_MINUTES} دقیقه اعتبار دارد.
        تاریخ و زمان {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}
        """

        try:
            send_mail(
                subject,
                message,
                settings.EMAIL_FROM,
                [email],
                fail_silently=False,
            )
        except SMTPException:
            raise SMTPException(_('خطا در ارسال ایمیل تایید: {e}'))

        return redirect('accounts:new-email-verify')


class NewEmailVerifyAPIView(GenericAPIView):
    serializer_class = NewEmailVerifySerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        validate_data = serializer.validated_data
        user = request.user
        user_email = Email.objects.get(user=user)

        if serializer.is_valid():
            user_email.email = validate_data['email']
            user_email.security_code = request.session['generated_security_code']
            user_email.is_verified = True
            user_email.sent_datetime = request.session['sent_datetime']
            user_email.created_datetime = timezone.now()
            message = {'detail': _('ایمیل با موفقیت بروزرسانی و تأیید شد.')}
            return Response(message, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# endregion


# region new phone

class NewPhoneAPIView(GenericAPIView):
    serializer_class = NewPhoneSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validate_data = serializer.validated_data
        phone = validate_data['phone']
        request.session['phone'] = phone
        user = request.user
        new_phone = Phone.objects.create(phone=phone, user=user)
        new_phone.generate_security_code()
        new_phone.send_confirmation()
        new_phone.save()
        return redirect('accounts:new-phone')


class NewPhoneVerifyAPIView(GenericAPIView):
    serializer_class = NewPhoneVerifySerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})

        if serializer.is_valid():
            message = {'detail': _('شماره تلفن با موفقیت تأیید شد.')}
            return Response(message, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# endregion


# region user account information

class UserAccountInformationAPIView(RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserAccountInformationSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

# endregion


# region address

class AddressListAPIView(GenericAPIView):
    pass


class AddressEditAPIView(GenericAPIView):
    pass

# endregion


# region logout

class LogoutAPIView(GenericAPIView):
    pass

# endregion

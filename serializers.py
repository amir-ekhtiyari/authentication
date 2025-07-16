from .models import Phone, Email
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.translation import gettext as _
from django.utils.encoding import force_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from email_validator import validate_email, EmailNotValidError
from smtplib import SMTPException
import datetime
import re
from django.utils import timezone
from rest_framework.exceptions import NotAcceptable

User = get_user_model()


# region register or login

class RegisterOrLoginSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(
        required=True, max_length=255, help_text='سلام!\nلطفا ایمیل یا شماره نلفن خود را وارد کنید'
    )

    def validate(self, attrs):
        email_or_phone = attrs.get('email_or_phone')

        if '@' in email_or_phone:
            try:
                validate_email(email_or_phone)
            except EmailNotValidError as e:
                raise serializers.ValidationError(_(str(e)))

            try:
                user = User.objects.get(email_address__email=email_or_phone)
                attrs['user'] = user
            except User.DoesNotExist:
                pass

        else:
            phone_number = email_or_phone.strip()

            if len(phone_number) > 13:
                raise serializers.ValidationError(_('شماره تلفن نباید بیش از ۱۳ رقم باشد.'))

            valid_formats = [
                r'^0\d{10}$',
                r'^\+98\d{10}$',
            ]

            valid = False
            for format in valid_formats:
                if re.match(format, phone_number):
                    valid = True
                    break

            if not valid:
                raise serializers.ValidationError(_('شماره تلفن باید با ۰ یا +۹۸ شروع شود و ۱۰ رقم داشته باشد.'))

        try:
            user = User.objects.get(phone_number__phone=email_or_phone)
            attrs['user'] = user
        except User.DoesNotExist:
            pass

        return attrs


# endregion


# region register

class RegisterSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(min_length=6, max_length=68, write_only=True, required=True)

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            raise serializers.ValidationError(_('رمزهای عبور مطابقت ندارند.'))

        return attrs


class RegisterVerifyEmailSerializer(serializers.Serializer):
    security_code = serializers.CharField(max_length=settings.TOKEN_LENGTH, required=True)

    def validate(self, attrs):
        email = self.context['request'].session.get('user_email')
        security_code = attrs.get('security_code')

        try:
            email_instance = Email.objects.get(email=email)
        except Email.DoesNotExist:
            raise serializers.ValidationError(_("ایمیل ارسالی شما یافت نشد."))

        if email_instance.security_code != security_code:
            raise serializers.ValidationError(_("کد امنیتی شما اشتباه است."))

        if email_instance.is_verified:
            raise serializers.ValidationError(_("این ایمیل قبلاً تأیید شده است."))

        email_instance.check_verification(security_code)

        return attrs


class RegisterVerifyPhoneSerializer(serializers.Serializer):
    security_code = serializers.CharField(max_length=settings.TOKEN_LENGTH, required=True)

    def validate(self, attrs):
        phone = self.context['request'].session.get('user_phone')
        security_code = attrs.get('security_code')

        try:
            phone_instance = Phone.objects.get(phone=phone)
        except Phone.DoesNotExist:
            raise serializers.ValidationError(_("شماره تلفن ارسالی شما یافت نشد."))

        if phone_instance.security_code != security_code:
            raise serializers.ValidationError(_("کد امنیتی شما اشتباه است."))

        if phone_instance.is_verified:
            raise serializers.ValidationError(_("این شماره تلفن قبلاً تأیید شده است."))

        phone_instance.check_verification(security_code)

        return attrs


# endregion


# region login with password

class LoginPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True, required=True
    )


# endregion


# region login with otp

class LoginEmailOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get('email')
        try:
            validate_email(email)
            attrs['email'] = email
            return attrs
        except EmailNotValidError as e:
            raise serializers.ValidationError(_(str(e)))


class LoginVerifyEmailSerializer(serializers.Serializer):
    security_code = serializers.CharField(max_length=settings.TOKEN_LENGTH, required=True)

    def validate(self, attrs):
        email = self.context['request'].session.get('email')
        security_code = attrs.get('security_code')

        try:
            email_instance = Email.objects.get(email=email)
        except Email.DoesNotExist:
            raise serializers.ValidationError(_("ایمیل ارسالی شما یافت نشد."))

        if email_instance.security_code != security_code:
            raise serializers.ValidationError(_("کد امنیتی شما اشتباه است."))

        email_instance.is_verified = False
        email_instance.check_verification(security_code)

        return attrs


class LoginPhoneOTPSerializer(serializers.Serializer):
    phone = serializers.CharField(required=True)

    def validate(self, attrs):
        phone = attrs.get('phone')
        phone_number = phone.strip()

        if len(phone_number) > 13:
            raise serializers.ValidationError(_('شماره تلفن نباید بیش از ۱۳ رقم باشد.'))

        valid_formats = [
            r'^0\d{10}$',
            r'^\+98\d{10}$',
        ]

        valid = False
        for format in valid_formats:
            if re.match(format, phone_number):
                valid = True
                break

        if not valid:
            raise serializers.ValidationError(_('شماره تلفن باید با ۰ یا +۹۸ شروع شود و ۱۰ رقم داشته باشد.'))

        return attrs


class LoginVerifyPhoneSerializer(serializers.Serializer):
    security_code = serializers.CharField(max_length=settings.TOKEN_LENGTH, required=True)

    def validate(self, attrs):
        phone = self.context['request'].session.get('phone')
        security_code = attrs.get('security_code')

        try:
            phone_instance = Phone.objects.get(phone=phone)
        except Phone.DoesNotExist:
            raise serializers.ValidationError(_("شماره تلفن ارسالی شما یافت نشد."))

        if phone_instance.security_code != security_code:
            raise serializers.ValidationError(_("کد امنیتی شما اشتباه است."))

        phone_instance.is_verified = False
        phone_instance.check_verification(security_code)

        return attrs


# endregion


# region login with Google

class LoginGoogleSerializer(serializers.Serializer):
    pass


# endregion


# region login password reset

class LoginPasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email_address__email=email).exists():
            user = User.objects.get(email_address__email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            request = self.context.get('request')
            current_site = get_current_site(request).domain
            relative_link = reverse(
                'accounts:login-password-rest-confirm', kwargs={'uidb64': uidb64, 'token': token}
            )
            abslink = f"http://{current_site}{relative_link}"
            print(abslink)
            subject = _('تغییر رمز عبور')
            message = f"""
            {settings.EMAIL_SUBJECT_PREFIX} :

            سلام {user.username}

            این ایمیل به درخواست شما برای بازیابی کلمه عبور در به فود برای شما ارسال شده است.
            برای تغییر کلمه عبور لینک زیر را باز کنید:
            لطفاً توجه داشته باشید، این لینک پس از 48 ساعت منقضی خواهد شد.
            تاریخ و زمان {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

            {abslink}
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
                raise SMTPException(_('خطا در ارسال ایمیل : {e}'))

        return super().validate(attrs)


class LoginSetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(min_length=6, max_length=68, write_only=True, required=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)
    token = serializers.CharField(min_length=3, write_only=True)

    class Meta:
        fields = ['password', 'password2', 'uidb64', 'token']

    def validate(self, attrs):
        try:
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            password = attrs.get('password')
            password2 = attrs.get('password2')

            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("لینک تنظیم مجدد رمز عبور نامعتبر است یا منقضی شده است.", 401)
            if password != password2:
                raise AuthenticationFailed("رمز های عبور مطابقت ندارند.")
            user.set_password(password)
            user.save()
            return user, attrs
        except Exception as e:
            return AuthenticationFailed("لینک تنظیم مجدد رمز عبور نامعتبر است یا منقضی شده است.")


# endregion


# region change password

class ChangePasswordSerializers(serializers.ModelSerializer):
    password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, write_only=True)
    new_password2 = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = ['password', 'new_password', 'new_password2']

    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise ValidationError('رمز عبور فعلی اشتباه است.')
        return value

    def validate(self, data):
        if data['new_password'] != data['new_password2']:
            raise ValidationError('رمزهای عبور جدید مطابقت ندارند.')
        validate_password(data['new_password'], self.context['request'].user)
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


# endregion


# region password reset

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get('email')
        user = self.context['request'].user

        if email != user.email:
            raise ValidationError("شما مجاز به تغییر رمز عبور خود نیستید.")
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        request = self.context.get('request')
        current_site = get_current_site(request).domain
        relative_link = reverse(
            'accounts:login-password-rest-confirm', kwargs={'uidb64': uidb64, 'token': token}
        )
        abslink = f"http://{current_site}{relative_link}"
        print(abslink)
        subject = _('تغییر رمز عبور')
        message = f"""
        {settings.EMAIL_SUBJECT_PREFIX} :

        سلام {user.username}

        این ایمیل به درخواست شما برای بازیابی کلمه عبور در به فود برای شما ارسال شده است.
        برای تغییر کلمه عبور لینک زیر را باز کنید:
        لطفاً توجه داشته باشید، این لینک پس از 48 ساعت منقضی خواهد شد.
        تاریخ و زمان {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        {abslink}
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
            raise SMTPException(_('خطا در ارسال ایمیل : {e}'))

        return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(min_length=6, max_length=68, write_only=True, required=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)
    token = serializers.CharField(min_length=3, write_only=True)

    class Meta:
        fields = ['password', 'password2', 'uidb64', 'token']

    def validate(self, attrs):
        try:
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            password = attrs.get('password')
            password2 = attrs.get('password2')

            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("لینک تنظیم مجدد رمز عبور نامعتبر است یا منقضی شده است.", 401)
            if password != password2:
                raise AuthenticationFailed("رمز های عبور مطابقت ندارند.")
            user.set_password(password)
            user.save()
            return user, attrs
        except Exception as e:
            return AuthenticationFailed("لینک تنظیم مجدد رمز عبور نامعتبر است یا منقضی شده است.")


# endregion


# region new email

class NewEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get('email')

        try:
            validate_email(email)
        except EmailNotValidError as e:
            raise serializers.ValidationError(_(str(e)))

        try:
            user = User.objects.get(email_address__email=email)
            if user:
                raise serializers.ValidationError('این ایمیل توسط شخص دیگری تایید شده است.')

        except User.DoesNotExist:
            pass

        return attrs


class NewEmailVerifySerializer(serializers.Serializer):
    security_code = serializers.CharField(max_length=settings.TOKEN_LENGTH, required=True)

    def validate(self, attrs):
        generated_security_code = self.context['request'].session.get('generated_security_code')
        entered_security_code = attrs.get('security_code')
        expiration_date = self.context['request'].session.get('expiration_date')
        print(generated_security_code, entered_security_code, expiration_date)

        if entered_security_code != generated_security_code:
            raise serializers.ValidationError(_("کد امنیتی شما اشتباه است."))

        if expiration_date <= timezone.now():
            raise serializers.ValidationError(_("کد امنیتی شما منقضی شده است."))

        return attrs


# endregion


# region new phone

class NewPhoneSerializer(serializers.Serializer):
    phone = serializers.CharField(required=True)

    def validate(self, attrs):
        phone = attrs.get('phone')
        phone_number = phone.strip()

        if len(phone_number) > 13:
            raise serializers.ValidationError(_('شماره تلفن نباید بیش از ۱۳ رقم باشد.'))

        valid_formats = [
            r'^0\d{10}$',
            r'^\+98\d{10}$',
        ]

        valid = False
        for format in valid_formats:
            if re.match(format, phone_number):
                valid = True
                break

        if not valid:
            raise serializers.ValidationError(_('شماره تلفن باید با ۰ یا +۹۸ شروع شود و ۱۰ رقم داشته باشد.'))

        try:
            user = User.objects.get(phone_number__phone=phone)
            if user:
                raise serializers.ValidationError('این شماره تلفن توسط شخص دیگری تایید شده است.')

        except User.DoesNotExist:
            pass

        return attrs


class NewPhoneVerifySerializer(serializers.Serializer):
    security_code = serializers.CharField(max_length=settings.TOKEN_LENGTH, required=True)

    def validate(self, attrs):
        phone = self.context['request'].session.get('phone')
        security_code = attrs.get('security_code')

        try:
            phone_instance = Phone.objects.get(phone=phone)
        except Email.DoesNotExist:
            raise serializers.ValidationError(_("شماره تلفن ارسالی شما یافت نشد."))

        if phone_instance.security_code != security_code:
            raise serializers.ValidationError(_("کد امنیتی شما اشتباه است."))

        if phone_instance.is_verified:
            raise serializers.ValidationError(_("این شماره تلفن قبلاً تأیید شده است."))

        phone_instance.check_verification(security_code)

        return attrs


# endregion


# region user account information

class UserAccountInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'national_code', 'first_name', 'last_name', 'bio', 'birthday', 'gender')


# endregion


# region address

class AddressListSerializer(serializers.Serializer):
    pass


class AddressEditSerializer(serializers.Serializer):
    pass


# endregion


# region logout

class LogoutSerializer(serializers.Serializer):
    pass

# endregion

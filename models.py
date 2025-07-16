import random
import datetime
import os
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from django.conf import settings
from django.utils.translation import gettext as _
from django.core.mail import send_mail
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import NotAcceptable
from django_resized import ResizedImageField
from phonenumber_field.modelfields import PhoneNumberField
from smtplib import SMTPException
from kavenegar import *


class UserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have "is_staff=True."')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have "is_superuser=True."')

        return self.create_user(username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.BigAutoField(primary_key=True, editable=False)
    username = models.CharField(max_length=250, unique=True)
    national_code = models.CharField(max_length=10, null=True, blank=True)
    first_name = models.CharField(max_length=250, null=True, blank=True)
    last_name = models.CharField(max_length=250, null=True, blank=True)
    bio = models.TextField(max_length=500, null=True, blank=True)
    birthday = models.DateField(null=True, blank=True)
    gender = models.CharField(
        max_length=1,
        choices=[('M', 'man'), ('F', 'woman'), ('O', 'other')],
        null=True,
        blank=True,
    )
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_datetime = models.DateTimeField(null=True, blank=True, auto_now=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_restaurant_owner = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'

    class Meta:
        db_table = "User"
        ordering = ['-created_datetime']
        indexes = [
            models.Index(fields=['username']),
        ]

    def get_absolute_url(self):
        return f"/users/{self.id}"

    def __str__(self):
        return f'{self.username}'


class Email(models.Model):
    user = models.OneToOneField(User, related_name='email_address', on_delete=models.CASCADE)
    email = models.EmailField(unique=True)
    security_code = models.CharField(max_length=120)
    is_verified = models.BooleanField(default=False)
    sent_datetime = models.DateTimeField(null=True)
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_datetime = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "Email"
        ordering = ('-created_datetime',)

    def __str__(self):
        return f'{self.email}'

    def generate_security_code(self):
        self.security_code = random.randint(100000, 999999)
        return self.security_code

    def is_security_code_expired(self):
        expiration_date = self.sent_datetime + datetime.timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES)
        return expiration_date <= timezone.now()

    def send_confirmation(self):
        subject = _('email verification')
        message = f"""
        {settings.EMAIL_SUBJECT_PREFIX} :
        hello {self.user.username}

        your code for verifying your email is {self.security_code}

        this code will expire in {settings.TOKEN_EXPIRE_MINUTES} minutes.
        do not share this code with anyone.
        if you did not request this email, you can ignore it.
        date and time : {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        """

        try:
            send_mail(
                subject,
                message,
                settings.EMAIL_FROM,
                [self.email],
                fail_silently=False,
            )
        except SMTPException:
            raise SMTPException(_('Error sending verification email: {e}'))

        self.sent_datetime = timezone.now()
        self.save()

    def check_verification(self, security_code):
        if (
                not self.is_security_code_expired() and
                security_code == self.security_code and
                not self.is_verified
        ):
            self.is_verified = True
            self.user.is_verified = True
            self.user.save()
            self.save()
        else:
            raise NotAcceptable(_("Your security code is incorrect, expired, or this email has already been verified."))

        return self.is_verified


class Phone(models.Model):
    user = models.OneToOneField(User, related_name='phone_number', on_delete=models.CASCADE, verbose_name="کاربر")
    phone = PhoneNumberField(unique=True, verbose_name="شماره تلفن")
    security_code = models.CharField(max_length=120, verbose_name="کد امنیتی")
    is_verified = models.BooleanField(default=False, verbose_name="تایید شده است")
    sent_datetime = models.DateTimeField(null=True, verbose_name="ارسال شده در")
    created_datetime = models.DateTimeField(auto_now_add=True, verbose_name="زمان ایجاد")
    updated_datetime = models.DateTimeField(auto_now=True, verbose_name="زمان بروزرسانی")

    class Meta:
        db_table = "Phone"
        ordering = ('-created_datetime',)
        verbose_name = "شماره تلفن"
        verbose_name_plural = "شماره‌های تلفن"

    def __str__(self):
        return self.phone.as_e164

    def generate_security_code(self):
        self.security_code = random.randint(100000, 999999)
        return self.security_code

    def is_security_code_expired(self):
        expiration_date = self.sent_datetime + datetime.timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES)
        return expiration_date <= timezone.now()

    def send_confirmation(self):
        try:
            api = KavenegarAPI(settings.KAVENEGAR_API_KEY)
            params = {
                'receptor': f'{self.phone}',
                'template': 'phone-verify',
                'token': f'{self.security_code}',
                'token2': f'{settings.TOKEN_EXPIRE_MINUTES}',
                'token10': f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                'type': 'sms',
            }
            response = api.verify_lookup(params)
            print(response)
            self.sent_datetime = timezone.now()
            self.save()

        except Exception as e:
            print(f"خطا در ارسال پیامک کاوه نگار: {e}")
            return Response({'message': _('خطا در ارسال کد تایید.')}, status=status.HTTP_400_BAD_REQUEST)

    def check_verification(self, security_code):
        if (
                not self.is_security_code_expired() and
                security_code == self.security_code and
                not self.is_verified
        ):
            self.is_verified = True
            self.user.is_verified = True
            self.user.save()
            self.save()
        else:
            raise NotAcceptable(_("کد امنیتی شما اشتباه است، منقضی شده است، یا این تلفن قبلاً تأیید شده است."))

        return self.is_verified


class UserImage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="images", verbose_name="کاربر")
    image = ResizedImageField(
        size=[500, 500],
        crop=['middle', 'center'],
        quality=75,
        upload_to='user_image',
        blank=True,
        verbose_name="تصویر",
    )
    alt = models.CharField(max_length=250, blank=True, verbose_name="متن جایگزین")

    class Meta:
        db_table = "UserImage"
        verbose_name = "تصویر کاربر"
        verbose_name_plural = "تصاویر کاربر"

    def delete(self, *args, **kwargs):
        storage, path = self.image.storage, self.image.path
        storage.delete(path)
        super().delete(*args, **kwargs)

    def __str__(self):
        return f"{self.alt if self.alt else 'بدون متن جایگزین'}"

    def save(self, *args, **kwargs):
        if not self.alt:
            filename = os.path.basename(self.image.name)
            self.alt = os.path.splitext(filename)[0]
        super().save(*args, **kwargs)


class Address(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="addresses", verbose_name="کاربر")
    title = models.CharField(max_length=250, blank=True, verbose_name="عنوان")
    address = models.TextField(max_length=500, blank=True, verbose_name="آدرس")
    city = models.CharField(max_length=250, blank=True, verbose_name="شهر")
    state = models.CharField(max_length=250, blank=True, verbose_name="استان")
    country = models.CharField(max_length=250, blank=True, verbose_name="کشور")
    postal_code = models.CharField(max_length=250, blank=True, verbose_name="کد پستی")
    is_default = models.BooleanField(default=False, verbose_name="پیش‌فرض")

    class Meta:
        db_table = "Address"
        verbose_name = "آدرس"
        verbose_name_plural = "آدرس‌ها"

    def __str__(self):
        return f"{self.user} - {self.title} - {self.address}"

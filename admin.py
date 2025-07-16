from django.contrib import admin
from . import models


class UserImageInline(admin.TabularInline):
    model = models.UserImage
    extra = 0


class PhoneNumberInline(admin.TabularInline):
    model = models.Phone
    extra = 0


class EmailInline(admin.TabularInline):
    model = models.Email
    extra = 0


class AddressInline(admin.TabularInline):
    model = models.Address
    extra = 0


@admin.register(models.User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'username', 'first_name', 'last_name', 'is_verified', 'is_active', 'is_staff', 'is_superuser',
        'email_address', 'phone_number'
    )
    fields = (
        'id', 'username', 'password', 'national_code', 'first_name', 'last_name', 'bio', 'birthday', 'gender',
        'created_datetime', 'updated_datetime', 'is_verified', 'is_active', 'is_staff', 'is_superuser'
    )
    readonly_fields = ('id', 'created_datetime', 'updated_datetime')
    list_display_links = ('id', 'username')
    list_filter = ('gender', 'created_datetime', 'updated_datetime', 'is_active', 'is_staff', 'is_superuser')
    search_fields = ('username', 'national_code', 'first_name', 'last_name')
    date_hierarchy = 'created_datetime'
    inlines = [PhoneNumberInline, EmailInline, AddressInline, UserImageInline]


@admin.register(models.Email)
class EmailAdmin(admin.ModelAdmin):
    list_display = ('user', 'email', 'is_verified', 'sent_datetime', 'created_datetime', 'updated_datetime')
    fields = ('user', 'email', 'security_code', 'is_verified', 'sent_datetime', 'created_datetime', 'updated_datetime')
    readonly_fields = ('sent_datetime', 'created_datetime', 'updated_datetime')
    list_filter = ('user', 'email', 'is_verified', 'sent_datetime', 'created_datetime', 'updated_datetime')
    search_fields = ('user', 'email')
    date_hierarchy = 'created_datetime'


@admin.register(models.Phone)
class PhoneNumberAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone', 'is_verified')
    fields = ('user', 'phone', 'security_code', 'is_verified', 'sent_datetime', 'created_datetime', 'updated_datetime')
    readonly_fields = ('sent_datetime', 'created_datetime', 'updated_datetime')
    list_filter = ('user', 'phone', 'is_verified', 'sent_datetime', 'created_datetime', 'updated_datetime')
    search_fields = ('user', 'phone')
    date_hierarchy = 'created_datetime'


@admin.register(models.UserImage)
class UserImageAdmin(admin.ModelAdmin):
    list_display = ('user',)
    fields = ('user', 'image', 'alt')
    list_filter = ('user',)
    search_fields = ('user', 'image', 'alt')


@admin.register(models.Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_default')
    fields = ('user', 'title', 'address', 'city', 'state', 'country', 'postal_code', 'is_default')
    list_filter = ('user', 'city', 'state', 'country', 'is_default')
    search_fields = ('user', 'title', 'address', 'city', 'state', 'country', 'postal_code', 'is_default')

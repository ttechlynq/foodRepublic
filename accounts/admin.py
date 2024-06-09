from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from  .models import User, UserProfile
# Register your models here.


class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'first_name', 'last_name', 'email', 'role', 'is_active', 'phone_number')
    ordeing = ('-date_joined')
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


admin.site.register(User, CustomUserAdmin)
admin.site.register(UserProfile)
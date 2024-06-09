from django.contrib import admin
from .models import Vendor
# Register your models here.


class VendorAdmin(admin.ModelAdmin):
    list_display = ('user', 'user_profile', 'vendor_name', 'is_approved', 'created_at', 'modified_date')
    list_display_links = ('user', 'vendor_name')

admin.site.register(Vendor, VendorAdmin)
from django.db import models
from accounts.models import User, UserProfile



class Vendor(models.Model):
    user = models.OneToOneField(User, related_name='user', on_delete=models.CASCADE)
    user_profile = models.OneToOneField(UserProfile, related_name='userProfile', on_delete=models.CASCADE)
    vendor_name = models.CharField(max_length=64)
    vendor_license = models.ImageField(upload_to='vendor/license', blank=True, null=True)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.vendor_name

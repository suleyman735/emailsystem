from django.contrib import admin

# Register your models here.

from .models import *

# Register your models here.
class UserAdmin(admin.ModelAdmin):
    list_display = ['email',]
    # list_filter = ['lang']

admin.site.register(UserAccount,UserAdmin)
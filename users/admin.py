from django.contrib import admin
from users.models import CustomUser, Credits, BulkCredits, APICredits

# Register your models here.
class CreditsInline(admin.TabularInline):
    model = Credits
    extra = 1

class BulkCreditsInline(admin.TabularInline):
    model = BulkCredits
    extra = 1

class APICreditsInline(admin.TabularInline):
    model = APICredits
    extra = 1

@admin.register(CustomUser)
class CustomuserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_superuser', 'is_staff', 'is_active', 'last_login', 'date_joined')
    search_fields = ('username', 'email')
    inlines = [CreditsInline, BulkCreditsInline, APICreditsInline]
    readonly_fields = ('is_superuser', 'is_staff', 'is_active', 'last_login', 'date_joined')
    ordering = ('-date_joined',)
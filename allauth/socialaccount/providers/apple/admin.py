from django import forms
from django.contrib import admin

from allauth.socialaccount.providers.apple.models import AppleSocialApp


class AppleSocialAppForm(forms.ModelForm):
    class Meta:
        model = AppleSocialApp
        exclude = ['key', 'secret']
        widgets = {
            'client_id': forms.TextInput(attrs={'size': '100'}),
            'team_id': forms.TextInput(attrs={'size': '100'}),
            'key_id': forms.TextInput(attrs={'size': '100'}),
        }


class SocialAppAdmin(admin.ModelAdmin):
    form = AppleSocialAppForm
    list_display = ('name', 'provider',)
    filter_horizontal = ('sites',)


admin.site.register(AppleSocialApp, SocialAppAdmin)

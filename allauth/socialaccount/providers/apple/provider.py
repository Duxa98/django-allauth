from allauth.socialaccount import app_settings
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider


class AppleAccount(ProviderAccount):

    def to_str(self):
        first_name = self.account.extra_data.get('first_name', '')
        last_name = self.account.extra_data.get('last_name', '')
        name = ' '.join([first_name, last_name]).strip()
        return name or super(AppleAccount, self).to_str()


class AppleProvider(OAuth2Provider):
    id = 'apple'
    name = 'Apple'
    account_class = AppleAccount

    def get_auth_params(self, request, action):
        ret = super(AppleProvider, self).get_auth_params(request, action)
        if action == 'authenticate':
            ret['response_mode'] = 'form_post'
        return ret

    def get_default_scope(self):
        scope = []
        if app_settings.QUERY_EMAIL:
            scope.append('email')
        return scope

    def get_app(self, request):
        from allauth.socialaccount.providers.apple.models import AppleSocialApp
        return AppleSocialApp.objects.get_current(self.id, request)

    def extract_uid(self, data):
        return data.get('uid')

    def extract_common_fields(self, data):
        return dict(email=data.get('email'),
                    last_name=data.get('last_name'),
                    first_name=data.get('first_name'))


provider_classes = [AppleProvider]

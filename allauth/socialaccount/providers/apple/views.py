from allauth.socialaccount.providers.apple.utils import get_user_info_from_id_token
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.oauth2.views import OAuth2Adapter, OAuth2LoginView, OAuth2CallbackView

from .provider import AppleProvider

USER_FIELDS = ['first_name',
               'last_name',
               'email']


class AppleOAuth2Adapter(OAuth2Adapter):
    provider_id = AppleProvider.id
    access_token_url = 'https://appleid.apple.com/auth/token'
    authorize_url = 'https://appleid.apple.com/auth/authorize'
    public_key_url = 'https://appleid.apple.com/auth/keys'


    def complete_login(self, request, app, token, **kwargs):
        extra_data = {}

        id_token = kwargs['response'].get('id_token')
        access_token = token.token
        payload = get_user_info_from_id_token(self.public_key_url, id_token, app, access_token=access_token)

        extra_data['uid'] = payload['sub']
        email = payload.get('email')
        if email:
            extra_data['email'] = email

        return self.get_provider().sociallogin_from_response(request, extra_data)


def apple_get_client(self, request, app):
    callback_url = self.adapter.get_callback_url(request, app)
    provider = self.adapter.get_provider()
    scope = provider.get_scope(request)
    client = OAuth2Client(self.request, app.client_id, app.generating_client_secret,
                          self.adapter.access_token_method,
                          self.adapter.access_token_url,
                          callback_url,
                          scope,
                          scope_delimiter=self.adapter.scope_delimiter,
                          headers=self.adapter.headers,
                          basic_auth=self.adapter.basic_auth)
    return client


class AppleLoginView(OAuth2LoginView):
    def get_client(self, request, app):
        return apple_get_client(self, request, app)

class AppleCallbackView(OAuth2CallbackView):
    def get_client(self, request, app):
        return apple_get_client(self, request, app)

oauth2_login = AppleLoginView.adapter_view(AppleOAuth2Adapter)
oauth2_callback = AppleCallbackView.adapter_view(AppleOAuth2Adapter)

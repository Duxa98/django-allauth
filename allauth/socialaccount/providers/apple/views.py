import json
import hashlib

import jwt
import requests
from jwt import PyJWTError
from jwt.utils import base64url_encode
from jwt.algorithms import RSAAlgorithm
from allauth.socialaccount.providers.oauth2.views import OAuth2Adapter, OAuth2LoginView, OAuth2CallbackView

from django.core.exceptions import ValidationError

from .provider import AppleProvider

USER_FIELDS = ['first_name',
               'last_name',
               'email']


class AppleOAuth2Adapter(OAuth2Adapter):
    provider_id = AppleProvider.id
    access_token_url = 'https://appleid.apple.com/auth/token'
    authorize_url = 'https://appleid.apple.com/auth/authorize'
    public_key_url = 'https://appleid.apple.com/auth/keys'

    def validate_access_token(self, access_token, at_hash):
        access_token_ascii = access_token.encode('ascii')
        at_hash_ascii = at_hash.encode('ascii')

        hash_obj = hashlib.sha256()
        hash_obj.update(access_token_ascii)
        left_part_of_hash = hash_obj.digest()[:len(hash_obj.digest()) // 2]
        my_hash = base64url_encode(left_part_of_hash)

        return my_hash == at_hash_ascii

    def validate_id_token(self, app, id_token, access_token):
        jwtset = requests.get(url=self.public_key_url).json()['keys'][0]
        public_key = RSAAlgorithm.from_jwk(json.dumps(jwtset))

        client_id = app.client_id

        try:
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=jwtset['alg'],
                audience=client_id
            )
        except PyJWTError as e:
            raise PyJWTError(f'\'{e}\' exception in validate_user')
        except Exception as e:
            raise ValidationError(f'\'{e}\' not PyJWTError exception in validate_user')
        else:
            at_hash = payload['at_hash']
            if not self.validate_access_token(access_token, at_hash):
                raise ValidationError('access_token is not for this user')
            return payload

    def complete_login(self, request, app, token, **kwargs):

        extra_data = {}

        id_token = kwargs['response'].get('id_token')
        access_token = token.token
        payload = self.validate_id_token(app, id_token, access_token)

        extra_data['uid'] = payload['sub']
        email = payload.get('email')
        if email:
            extra_data['email'] = email

        return self.get_provider().sociallogin_from_response(request, extra_data)


oauth2_login = OAuth2LoginView.adapter_view(AppleOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(AppleOAuth2Adapter)

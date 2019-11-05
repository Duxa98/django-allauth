from datetime import datetime
import requests
import jwt
import hashlib
import json
from jwt import PyJWTError
from jwt.utils import base64url_encode
from jwt.algorithms import RSAAlgorithm

from django.core.exceptions import ValidationError as DjangoValidationError

def generate_client_secret(app):
    team_id = app.team_id
    client_id = app.client_id
    key_id = app.key_id

    time = int(datetime.timestamp(datetime.utcnow()))

    headers = {
        'alg': 'ES256',
        'kid': key_id
    }
    claims = {
        'iss': team_id,
        'iat': time,
        'exp': time + 86400 * 180,
        'aud': 'https://appleid.apple.com',
        'sub': client_id
    }

    key = app.auth_key.read()

    client_secret = jwt.encode(payload=claims, headers=headers, key=key, algorithm='ES256')

    return client_secret


def get_user_info_from_id_token(public_key_url, id_token, app, access_token=None, code=None):
    jwts = requests.get(url=public_key_url).json()['keys'][0]
    public_key = RSAAlgorithm.from_jwk(str(json.dumps(jwts)))

    alg = jwts['alg']

    try:
        info = jwt.decode(
            id_token,
            public_key,
            algorithms=alg,
            audience=app.client_id
        )
    except PyJWTError as e:
        raise PyJWTError(f'\'{e}\' exception in validate_user')
    except Exception as e:
        raise DjangoValidationError(f'\'{e}\' not PyJWTError exception in validate_user')
    else:
        if access_token:
            if not verify_mobile_data(access_token, info['at_hash']):
                raise DjangoValidationError('access_token or identity token is not for this user')
        if code:
            if not verify_mobile_data(code, info['c_hash']):
                raise DjangoValidationError('authorization_code or identity token is not for this user')
        return info


def verify_mobile_data(data, data_hash):
    data_ascii = data.encode('ascii')
    data_hash_ascii = data_hash.encode('ascii')

    hash_obj = hashlib.sha256()
    hash_obj.update(data_ascii)
    left_part_of_hash = hash_obj.digest()[:len(hash_obj.digest()) // 2]
    my_hash = base64url_encode(left_part_of_hash)

    return my_hash == data_hash_ascii

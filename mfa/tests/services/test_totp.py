import json

import pyotp
import pytest

from mfa.models import User_Keys

login_credentials = ['kwilkinson', 'TestPassword1!']


class TestTotp:
    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_totp_add(self, logged_in_client):
        url = '/mfa/totp/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert response.status_code == 201
        assert 'content' in content
        assert 'totp_data' in content
        assert 'qr' in content['totp_data']
        assert 'secret_key' in content['totp_data']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username, key_type='TOTP')
        assert uk

        response = logged_in_client.get(url)
        assert response.status_code == 403
        assert b'TOTP already configured for user:' in response.content

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_totp_verify(self, logged_in_client):
        url = '/mfa/totp/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        assert 'totp_data' in content
        assert 'qr' in content['totp_data']
        assert 'secret_key' in content['totp_data']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk

        secret_key = uk.properties['secret_key']
        totp_code = pyotp.TOTP(secret_key).now()

        url = f'/mfa/totp/verify'
        response = logged_in_client.get(url, data={'answer': totp_code})
        assert response.status_code == 200
        assert response.content == b'Success'

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_totp_enable_disable(self, logged_in_client):
        url = '/mfa/totp/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        assert 'totp_data' in content
        assert 'qr' in content['totp_data']
        assert 'secret_key' in content['totp_data']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk
        assert uk.enabled

        url = f'/mfa/totp'
        response = logged_in_client.post(url, data={'enabled': False})
        assert response.status_code == 200
        assert response.content == b'Disabled TOTP MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert not uk.enabled

        url = f'/mfa/totp'
        response = logged_in_client.post(url, data={'enabled': True})
        assert response.status_code == 200
        assert response.content == b'Enabled TOTP MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk.enabled

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_totp_set_default(self, logged_in_client):
        url = '/mfa/totp/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        assert 'totp_data' in content
        assert 'qr' in content['totp_data']
        assert 'secret_key' in content['totp_data']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk
        assert not uk.is_default

        url = f'/mfa/totp'
        response = logged_in_client.post(url, data={'default': True})
        print(response)
        assert response.status_code == 200
        assert response.content == b'Set TOTP as default MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk.is_default

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_totp_new_token(self, logged_in_client):
        url = '/mfa/totp/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        assert 'totp_data' in content
        assert 'qr' in content['totp_data']
        assert 'secret_key' in content['totp_data']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk
        assert not uk.is_default

        secret_key = uk.properties['secret_key']
        totp_code = pyotp.TOTP(secret_key).now()

        url = f'/mfa/totp/verify'
        response = logged_in_client.get(url, data={'answer': totp_code})
        assert response.status_code == 200
        assert response.content == b'Success'

        url = '/mfa/totp/token'
        response = logged_in_client.put(url)
        content = json.loads(response.content)
        assert 'content' in content
        assert 'totp_data' in content
        assert 'qr' in content['totp_data']
        assert 'secret_key' in content['totp_data']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk
        assert not uk.is_default

        secret_key = uk.properties['secret_key']
        totp_code = pyotp.TOTP(secret_key).now()

        url = f'/mfa/totp/verify'
        response = logged_in_client.get(url, data={'answer': totp_code})

        assert response.status_code == 200
        assert response.content == b'Success'

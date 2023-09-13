import json

import pytest

from mfa.models import User_Keys

login_credentials = ['kwilkinson', 'TestPassword1!']


class TestAllMFA:
    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_set_default(self, logged_in_client):
        url = '/mfa/email/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert response.status_code == 201
        assert 'content' in content
        assert 'Email Entry created for user' in content['content']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username, key_type='Email')
        assert uk

        url = '/mfa/text/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert response.status_code == 201
        assert 'content' in content
        assert 'Text Entry created for user' in content['content']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username, key_type='Text')
        assert uk

        url = '/mfa/totp/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert response.status_code == 201
        assert 'content' in content
        assert 'totp_data' in content
        assert 'qr' in content['totp_data']
        assert 'secret_key' in content['totp_data']
        assert 'TOTP Entry created for user' in content['content']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username, key_type='TOTP')
        assert uk

        # Set email as default
        url = '/mfa/email'

        response = logged_in_client.post(url, data={'default': True})
        assert response.status_code == 200
        user_keys = User_Keys.objects.filter(username=logged_in_client.auth_user.username)

        for key in user_keys:
            if key.key_type == 'Email':
                assert key.is_default
            else:
                assert not key.is_default

        url = '/mfa/text'

        response = logged_in_client.post(url, data={'default': True})
        assert response.status_code == 200
        user_keys = User_Keys.objects.filter(username=logged_in_client.auth_user.username)

        for key in user_keys:
            if key.key_type == 'Text':
                assert key.is_default
            else:
                assert not key.is_default

        url = '/mfa/totp'

        response = logged_in_client.post(url, data={'default': True})
        assert response.status_code == 200
        user_keys = User_Keys.objects.filter(username=logged_in_client.auth_user.username)

        for key in user_keys:
            if key.key_type == 'TOTP':
                assert key.is_default
            else:
                assert not key.is_default

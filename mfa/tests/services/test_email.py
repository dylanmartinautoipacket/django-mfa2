import json

import pytest

from mfa.Email import verify
from mfa.models import User_Keys

login_credentials = ['kwilkinson', 'TestPassword1!']


class TestEmail:
    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_email_add(self, logged_in_client):
        url = '/mfa/email/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert response.status_code == 201
        assert 'content' in content
        assert 'Email Entry created for user' in content['content']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username, key_type='Email')
        assert uk

        response = logged_in_client.get(url)
        assert response.status_code == 403
        assert b'Email already configured for user:' in response.content

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_email_enable_disable(self, logged_in_client):
        url = '/mfa/email/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk
        assert uk.enabled

        url = f'/mfa/email'
        response = logged_in_client.post(url, data={'enabled': False})
        assert response.status_code == 200
        assert response.content == b'Disabled Email MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert not uk.enabled

        url = f'/mfa/email'
        response = logged_in_client.post(url, data={'enabled': True})
        assert response.status_code == 200
        assert response.content == b'Enabled Email MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk.enabled

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_email_verify(self, logged_in_client, monkeypatch):
        url = '/mfa/email/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk

        class RequestObj:
            pass

        request = RequestObj
        request.session = {'email_secret': 12345}
        response = verify(request, 12345)
        assert response.content == b'Success'

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_email_set_default(self, logged_in_client):
        url = '/mfa/email/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk
        assert not uk.is_default

        url = f'/mfa/email'
        response = logged_in_client.post(url, data={'default': True})
        print(response)
        assert response.status_code == 200
        assert response.content == b'Set Email as default MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk.is_default

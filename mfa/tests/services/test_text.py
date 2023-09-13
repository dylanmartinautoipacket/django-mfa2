import json

import pytest

from mfa.models import User_Keys
from mfa.Text import verify

login_credentials = ['kwilkinson', 'TestPassword1!']


class TestText:
    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_text_add(self, logged_in_client):
        url = '/mfa/text/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert response.status_code == 201
        assert 'content' in content
        assert 'Text Entry created for user' in content['content']
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username, key_type='Text')
        assert uk

        response = logged_in_client.get(url)
        assert response.status_code == 403
        assert b'Text already configured for user:' in response.content

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_text_enable_disable(self, logged_in_client):
        url = '/mfa/text/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk
        assert uk.enabled

        url = f'/mfa/text'
        response = logged_in_client.post(url, data={'enabled': False})
        assert response.status_code == 200
        assert response.content == b'Disabled Text MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert not uk.enabled

        url = f'/mfa/text'
        response = logged_in_client.post(url, data={'enabled': True})
        assert response.status_code == 200
        assert response.content == b'Enabled Text MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk.enabled

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_text_verify(self, logged_in_client, monkeypatch):
        url = '/mfa/text/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk

        class RequestObj:
            pass

        request = RequestObj
        request.session = {'text_secret': 12345}
        response = verify(request, 12345)
        assert response.content == b'Success'

    @pytest.mark.django_db
    @pytest.mark.parametrize('logged_in_client', [login_credentials], indirect=['logged_in_client'])
    def test_text_set_default(self, logged_in_client):
        url = '/mfa/text/add'

        response = logged_in_client.get(url)
        content = json.loads(response.content)
        assert 'content' in content
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk
        assert not uk.is_default

        url = f'/mfa/text'
        response = logged_in_client.post(url, data={'default': True})
        print(response)
        assert response.status_code == 200
        assert response.content == b'Set Text as default MFA method.\n'
        uk = User_Keys.objects.get(username=logged_in_client.auth_user.username)
        assert uk.is_default

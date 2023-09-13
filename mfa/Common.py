import json

import pyotp
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned
from django.core.mail import EmailMessage
from django.http import HttpResponse
from rest_framework import status

from mfa.models import User_Keys

try:
    from django.urls import reverse
except:
    from django.core.urlresolver import reverse


def getToken(request):
    user = request.user
    if not user:
        return HttpResponse('User not found', status=status.HTTP_401_UNAUTHORIZED)

    secret_key = pyotp.random_base32()
    totp = pyotp.TOTP(secret_key)
    request.session['new_mfa_answer'] = totp.now()
    return HttpResponse(
        json.dumps(
            {
                'qr': pyotp.totp.TOTP(secret_key).provisioning_uri(
                    str(request.user.username), issuer_name=settings.TOKEN_ISSUER_NAME
                ),
                'secret_key': secret_key,
            }
        )
    )


def send(to, subject, body):
    from_email_address = settings.EMAIL_HOST_USER
    if '@' not in from_email_address:
        from_email_address = settings.DEFAULT_FROM_EMAIL
    From = '%s <%s>' % (settings.EMAIL_FROM, from_email_address)
    email = EmailMessage(subject, body, From, to)
    email.content_subtype = 'html'
    return email.send(False)


def get_redirect_url():
    return {
        'redirect_html': reverse(getattr(settings, 'MFA_REDIRECT_AFTER_REGISTRATION', 'mfa_home')),
        'reg_success_msg': getattr(settings, 'MFA_SUCCESS_REGISTRATION_MSG'),
    }


def enable_mfa_type(type, request):
    user = request.user
    if not user:
        return HttpResponse('User not found', status=status.HTTP_401_UNAUTHORIZED)

    try:
        user_key = User_Keys.objects.get(username=user.username, key_type=type)
    except MultipleObjectsReturned:
        return HttpResponse(
            f'Error: more than one {type} MFA entry for user {user.username}', status=status.HTTP_400_BAD_REQUEST
        )
    except User_Keys.DoesNotExist:
        return HttpResponse(f'Error: No {type} MFA entry for user {user.username}', status=status.HTTP_404_NOT_FOUND)

    user_key.enabled = True
    user_key.save()

    return HttpResponse(f'Enabled {type} MFA method.', status=status.HTTP_200_OK)


def disable_mfa_type(type, request):
    user = request.user
    if not user:
        return HttpResponse('User not found', status=status.HTTP_401_UNAUTHORIZED)

    try:
        user_key = User_Keys.objects.get(username=user.username, key_type=type)
    except MultipleObjectsReturned:
        return HttpResponse(
            f'Error: more than one {type} MFA entry for user {user.username}', status=status.HTTP_400_BAD_REQUEST
        )
    except User_Keys.DoesNotExist:
        return HttpResponse(f'Error: No {type} MFA entry for user {user.username}', status=status.HTTP_404_NOT_FOUND)

    user_key.enabled = False
    user_key.is_default = False
    user_key.save()

    return HttpResponse(f'Disabled {type} MFA method.', status=status.HTTP_200_OK)


def set_default_mfa_type(type, request):
    user = request.user
    if not user:
        return HttpResponse('User not found', status=status.HTTP_401_UNAUTHORIZED)

    try:
        user_key = User_Keys.objects.get(username=user.username, key_type=type)
    except MultipleObjectsReturned:
        return HttpResponse(
            f'Error: more than one {type} MFA entry for user {user.username}', status=status.HTTP_400_BAD_REQUEST
        )
    except User_Keys.DoesNotExist:
        return HttpResponse(f'Error: No {type} MFA entry for user {user.username}', status=status.HTTP_404_NOT_FOUND)

    # Make sure other MFA options are not default
    other_keys = User_Keys.objects.filter(username=user.username, is_default=True)
    for keys in other_keys:
        keys.is_default = False
        keys.save()

    user_key.is_default = True
    user_key.save()

    return HttpResponse(f'Set {type} as default MFA method.', status=status.HTTP_200_OK)


def remove_default_mfa_type(type, request):
    user = request.user
    if not user:
        return HttpResponse('User not found', status=status.HTTP_401_UNAUTHORIZED)

    try:
        user_key = User_Keys.objects.get(username=user.username, key_type=type)
    except MultipleObjectsReturned:
        return HttpResponse(
            f'Error: more than one {type} MFA entry for user {user.username}', status=status.HTTP_400_BAD_REQUEST
        )
    except User_Keys.DoesNotExist:
        return HttpResponse(f'Error: No {type} MFA entry for user {user.username}', status=status.HTTP_404_NOT_FOUND)

    user_key.is_default = False
    user_key.save()

    return HttpResponse(f'Removed {type} as default MFA method.', status=status.HTTP_200_OK)


def add_mfa_type(type, request):
    user = request.user
    if not user:
        return HttpResponse('User not found', status=status.HTTP_401_UNAUTHORIZED)

    user_keys = User_Keys.objects.filter(username=user.username, key_type=type)
    if len(user_keys) > 0:
        return HttpResponse(f'{type} already configured for user: {user.username}', status=status.HTTP_403_FORBIDDEN)

    is_default = False
    if 'default' in request.GET and request.GET['default']:
        is_default = True

    extra_data = {}
    if type == 'TOTP':
        extra_data = json.loads(getToken(request).content)
        new_uk = User_Keys.objects.create(
            username=user.username, key_type=type, properties=extra_data, is_default=is_default
        )
    else:
        new_uk = User_Keys.objects.create(username=user.username, key_type=type, is_default=is_default)

    new_uk.save()

    return HttpResponse(
        content=json.dumps({'content': f'{type} Entry created for user {user.username}', 'totp_data': extra_data}),
        status=status.HTTP_201_CREATED,
    )


def manage_mfa(type, request):
    if request.method != 'POST':
        return HttpResponse('Expected POST request', status=status.HTTP_400_BAD_REQUEST)

    responses = {}
    for option in request.POST:
        if option == 'default':
            if request.POST[option] == 'True':
                responses[option] = set_default_mfa_type(type, request)
            else:
                responses[option] = remove_default_mfa_type(type, request)

        if option == 'enabled':
            if request.POST[option] == 'True':
                responses[option] = enable_mfa_type(type, request)
            else:
                responses[option] = disable_mfa_type(type, request)

    response_message = b''
    status_code = 200
    for response in responses:
        response_message += responses[response].content + b'\n'
        if responses[response].status_code != 200:
            status_code = responses[response].status_code
    return HttpResponse(response_message, status=status_code)

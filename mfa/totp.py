import datetime
import json
import random

import pyotp
from django.core.exceptions import MultipleObjectsReturned
from django.http import HttpResponse
from django.shortcuts import render
from django.template import loader
from django.template.context_processors import csrf
from django.utils import timezone
from django.views.decorators.cache import never_cache
from rest_framework import status

from .Common import (
    add_mfa_type,
    disable_mfa_type,
    enable_mfa_type,
    get_redirect_url,
    getToken,
    manage_mfa,
    set_default_mfa_type,
)
from .models import *
from .views import login


def verify_login(request, username, token):
    for key in User_Keys.objects.filter(username=username, key_type='TOTP'):
        totp = pyotp.TOTP(key.properties['secret_key'])
        if totp.verify(token, valid_window=30):
            key.last_used = timezone.now()
            key.save()
            return [True, key.id]
    return [False]


def recheck(request):
    context = csrf(request)
    context['mode'] = 'recheck'
    if request.method == 'POST':
        if verify_login(request, request.user.username, token=request.POST['otp'])[0]:
            import time

            request.session['mfa']['rechecked_at'] = time.time()
            return HttpResponse(json.dumps({'recheck': True}), content_type='application/json')
        else:
            return HttpResponse(json.dumps({'recheck': False}), content_type='application/json')
    return render(request, 'TOTP/recheck.html', context)


@never_cache
def auth(request):
    context = csrf(request)
    if request.method == 'POST':
        tokenLength = len(request.POST['otp'])
        if tokenLength == 6:
            res = verify_login(request, request.session['base_username'], token=request.POST['otp'])
            if res[0]:
                mfa = {'verified': True, 'method': 'TOTP', 'id': res[1]}
                if getattr(settings, 'MFA_RECHECK', False):
                    mfa['next_check'] = datetime.datetime.timestamp(
                        (
                            datetime.datetime.now()
                            + datetime.timedelta(
                                seconds=random.randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX)
                            )
                        )
                    )
                request.session['mfa'] = mfa
                return login(request)
        context['invalid'] = True
    else:
        template = loader.get_template('admin/login.html')
        context.update(
            {
                'mfa_active': True,
                'invalid': False,
                'totp': True,
                'text': False,
                'email': False,
            }
        )
        return HttpResponse(template.render(context, request))

    template = loader.get_template('admin/login.html')
    context.update(
        {
            'mfa_active': True,
            'invalid': True,
            'totp': True,
            'text': False,
            'email': False,
        }
    )
    return HttpResponse(template.render(context, request))


def verify(
    request,
    value=None,
):
    if value is None:
        answer = request.GET['answer']
    else:
        answer = value

    # Get user's secret key
    try:
        uk = User_Keys.objects.get(username=request.user.username, key_type='TOTP')
    except:
        request.session['mfa_status'] = False
        return HttpResponse(f'Error, TOTP MFA entry for user {request.user.username} not found')

    secret_key = uk.properties['secret_key']
    totp = pyotp.TOTP(secret_key)
    if totp.verify(answer, valid_window=60):
        if (
            getattr(settings, 'MFA_ENFORCE_RECOVERY_METHOD', False)
            and not User_Keys.objects.filter(key_type='RECOVERY', username=request.user.username).exists()
        ):
            request.session['mfa_reg'] = {
                'method': 'TOTP',
                'name': getattr(settings, 'MFA_RENAME_METHODS', {}).get('TOTP', 'TOTP'),
            }
            return HttpResponse('RECOVERY')
        else:
            return HttpResponse('Success')
    else:
        return HttpResponse('Error')


@never_cache
def start(request):
    """Start Adding Time One Time Password (TOTP)"""
    context = get_redirect_url()
    context['RECOVERY_METHOD'] = getattr(settings, 'MFA_RENAME_METHODS', {}).get('RECOVERY', 'Recovery codes')
    context['method'] = {'name': getattr(settings, 'MFA_RENAME_METHODS', {}).get('TOTP', 'Authenticator')}
    return render(request, 'TOTP/Add.html', context)


def get_new_token(request):
    if request.method != 'PUT':
        return HttpResponse('Expected PUT request', status=status.HTTP_400_BAD_REQUEST)

    user = request.user
    if not user:
        return HttpResponse('User not found', status=status.HTTP_401_UNAUTHORIZED)

    try:
        user_key = User_Keys.objects.get(username=user.username, key_type='TOTP')
    except MultipleObjectsReturned:
        return HttpResponse(
            f'Error: more than one TOTP MFA entry for user {user.username}', status=status.HTTP_400_BAD_REQUEST
        )
    except User_Keys.DoesNotExist:
        return HttpResponse(f'Error: No TOTP MFA entry for user {user.username}', status=status.HTTP_404_NOT_FOUND)

    new_token = getToken(request).content

    # for key in user_key:
    user_key.properties = json.loads(new_token)
    user_key.save()

    return HttpResponse(
        content=json.dumps({'content': 'Token updated', 'totp_data': new_token.decode()}), status=status.HTTP_200_OK
    )


def add(request):
    return add_mfa_type('TOTP', request)


def set_default(request):
    return set_default_mfa_type('TOTP', request)


def disable(request):
    return disable_mfa_type('TOTP', request)


def enable(request):
    return enable_mfa_type('TOTP', request)


def manage(request):
    return manage_mfa('TOTP', request)

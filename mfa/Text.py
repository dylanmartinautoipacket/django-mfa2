import datetime
import random
from random import randint

from django.http import HttpResponse
from django.shortcuts import render
from django.template import loader
from django.template.context_processors import csrf
from django.views.decorators.cache import never_cache

from aip_app_users.models import LegacyUser
from aip_rest_api.sms_backend.twilio_backend import TwilioSMSBackend

from .Common import (
    add_mfa_type,
    disable_mfa_type,
    enable_mfa_type,
    manage_mfa,
    set_default_mfa_type,
)
from .models import *

# from django.template.context import RequestContext
from .views import login


def sendText(request, username, secret):
    """Send Text to the user after rendering `mfa_email_token_template`"""
    from django.contrib.auth import get_user_model

    User = get_user_model()
    key = getattr(User, 'USERNAME_FIELD', 'username')
    kwargs = {key: username}
    user = User.objects.get(**kwargs)
    phone_number = LegacyUser.objects.get(**kwargs).user_phone
    sms_backend = TwilioSMSBackend()
    message = f'Your iPacket one time password code is: {secret}'
    return sms_backend.send(message=message, to_number=phone_number)


@never_cache
def start(request):
    """Start adding email as a 2nd factor"""
    context = csrf(request)
    if request.method == 'POST':
        if request.session['text_secret'] == request.POST['otp']:  # if successful
            uk = User_Keys()
            uk.username = request.user.username
            uk.key_type = 'Text'
            uk.enabled = 1
            uk.save()
            from django.http import HttpResponseRedirect

            try:
                from django.core.urlresolvers import reverse
            except:
                from django.urls import reverse
            if (
                getattr(settings, 'MFA_ENFORCE_RECOVERY_METHOD', False)
                and not User_Keys.objects.filter(key_type='RECOVERY', username=request.user.username).exists()
            ):
                request.session['mfa_reg'] = {
                    'method': 'Text',
                    'name': getattr(settings, 'MFA_RENAME_METHODS', {}).get('Text', 'Text'),
                }
            else:
                return HttpResponseRedirect(reverse(getattr(settings, 'MFA_REDIRECT_AFTER_REGISTRATION', 'mfa_home')))
        context['invalid'] = True
    else:
        request.session['text_secret'] = str(randint(0, 100000))  # generate a random integer

        if sendText(request, request.user.username, request.session['text_secret']):
            context['sent'] = True
    return render(request, 'Text/Add.html', context)


@never_cache
def auth(request):
    """Authenticating the user by email."""
    context = csrf(request)
    if request.method == 'POST':
        if request.session['text_secret'] == request.POST['otp'].strip():
            uk = User_Keys.objects.get(username=request.session['base_username'], key_type='Text')
            mfa = {'verified': True, 'method': 'Text', 'id': uk.id}
            if getattr(settings, 'MFA_RECHECK', False):
                mfa['next_check'] = datetime.datetime.timestamp(
                    datetime.datetime.now()
                    + datetime.timedelta(seconds=random.randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX))
                )
            request.session['mfa'] = mfa

            from django.utils import timezone

            uk.last_used = timezone.now()
            uk.save()
            return login(request)
        context['invalid'] = True
    else:
        request.session['text_secret'] = str(randint(0, 100000))
        if sendText(request, request.session['base_username'], request.session['text_secret']):
            context['sent'] = True
        template = loader.get_template('admin/text_login.html')
        context.update({'mfa_active': True, 'invalid': False, 'text': True, 'email': False, 'totp': False})
        return HttpResponse(template.render(context, request))

    template = loader.get_template('admin/text_login.html')
    context.update({'mfa_active': True, 'invalid': True, 'text': True, 'email': False, 'totp': False})
    return HttpResponse(template.render(context, request))


def send_text(request):
    username = request.user.username
    secret = str(randint(0, 100000))
    request.session['text_secret'] = secret
    sendText(request, username, secret)
    return HttpResponse('Text sent')


def verify(request, value=None):
    if value is None:
        answer = request.GET['answer']
    else:
        answer = value

    if request.session['text_secret'] == answer:
        return HttpResponse('Success')
    else:
        return HttpResponse('Error')


def add(request):
    return add_mfa_type('Text', request)


def set_default(request):
    return set_default_mfa_type('Text', request)


def disable(request):
    return disable_mfa_type('Text', request)


def enable(request):
    return enable_mfa_type('Text', request)


def manage(request):
    return manage_mfa('Text', request)

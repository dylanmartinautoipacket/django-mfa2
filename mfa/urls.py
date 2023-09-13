from . import FIDO2, U2F, Email, Text, TrustedDevice, helpers, recovery, totp, views

# app_name='mfa'

try:
    from django.urls import re_path as url
except:
    from django.conf.urls import url
urlpatterns = [
    url(r'totp/start', totp.start, name='start_new_otop'),
    url(r'totp/verify', totp.verify, name='verify_otop'),
    url(r'totp/auth', totp.auth, name='totp_auth'),
    url(r'totp/recheck', totp.recheck, name='totp_recheck'),
    url(r'totp/add', totp.add, name='totp_add'),
    url(r'totp/token', totp.get_new_token, name='totp_new_token'),
    url(r'totp', totp.manage, name='totp_manage'),
    url(r'recovery/start', recovery.start, name='manage_recovery_codes'),
    url(r'recovery/getTokenLeft', recovery.getTokenLeft, name='get_recovery_token_left'),
    url(r'recovery/genTokens', recovery.genTokens, name='regen_recovery_tokens'),
    url(r'recovery/auth', recovery.auth, name='recovery_auth'),
    url(r'recovery/recheck', recovery.recheck, name='recovery_recheck'),
    url(r'email/start/', Email.start, name='start_email'),
    url(r'email/auth/', Email.auth, name='email_auth'),
    url(r'email/send', Email.send_email, name='email_send'),
    url(r'email/add', Email.add, name='email_add'),
    url(r'email', Email.manage, name='email_manage'),
    url(r'text/auth/', Text.auth, name='text_auth'),
    url(r'text/verify', Text.verify, name='text_verify'),
    url(r'text/send', Text.send_text, name='text_send'),
    url(r'text/add', Text.add, name='text_add'),
    url(r'text', Text.manage, name='text_manage'),
    url(r'u2f/$', U2F.start, name='start_u2f'),
    url(r'u2f/bind', U2F.bind, name='bind_u2f'),
    url(r'u2f/auth', U2F.auth, name='u2f_auth'),
    url(r'u2f/process_recheck', U2F.process_recheck, name='u2f_recheck'),
    url(r'u2f/verify', U2F.verify, name='u2f_verify'),
    url(r'fido2/$', FIDO2.start, name='start_fido2'),
    url(r'fido2/auth', FIDO2.auth, name='fido2_auth'),
    url(r'fido2/begin_auth', FIDO2.authenticate_begin, name='fido2_begin_auth'),
    url(r'fido2/complete_auth', FIDO2.authenticate_complete, name='fido2_complete_auth'),
    url(r'fido2/begin_reg', FIDO2.begin_registeration, name='fido2_begin_reg'),
    url(r'fido2/complete_reg', FIDO2.complete_reg, name='fido2_complete_reg'),
    url(r'fido2/recheck', FIDO2.recheck, name='fido2_recheck'),
    url(r'td/$', TrustedDevice.start, name='start_td'),
    url(r'td/add', TrustedDevice.add, name='add_td'),
    url(r'td/send_link', TrustedDevice.send_email, name='td_sendemail'),
    url(r'td/get-ua', TrustedDevice.getUserAgent, name='td_get_useragent'),
    url(r'td/trust', TrustedDevice.trust_device, name='td_trust_device'),
    url(r'u2f/checkTrusted', TrustedDevice.checkTrusted, name='td_checkTrusted'),
    url(r'u2f/secure_device', TrustedDevice.getCookie, name='td_securedevice'),
    url(r'^$', views.index, name='mfa_home'),
    url(r'goto/(.*)', views.goto, name='mfa_goto'),
    url(r'selct_method', views.show_methods, name='mfa_methods_list'),
    url(r'recheck', helpers.recheck, name='mfa_recheck'),
    url(r'toggleKey', views.toggleKey, name='toggle_key'),
    url(r'delete', views.delKey, name='mfa_delKey'),
    url(r'reset', views.reset_cookie, name='mfa_reset_cookie'),
]
# print(urlpatterns)

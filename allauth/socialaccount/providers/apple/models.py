from allauth.socialaccount.models import SocialApp

from django.db import models
from django.utils.translation import ugettext_lazy as _

from allauth.socialaccount.providers.apple.utils import generate_client_secret


class AppleSocialApp(SocialApp):

    team_id = models.CharField(verbose_name=_('team id'),
                               max_length=191,
                               help_text=_('Apple TeamID'),
                               blank=False)
    key_id = models.CharField(verbose_name=_('key id'),
                              max_length=256,
                              help_text=_('Apple KeyID'),
                              blank=False)

    auth_key = models.FileField(verbose_name=_('authentication key'),
                                help_text=_('Apple AuthKey'),
                                blank=False)

    @property
    def generating_client_secret(self):
        return generate_client_secret(self)

    class Meta:
        verbose_name = _('social application')
        verbose_name_plural = _('social applications')

    def __str__(self):
        return self.name


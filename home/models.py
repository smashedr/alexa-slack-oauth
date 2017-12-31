from __future__ import unicode_literals

from django.db import models


class TokenDatabase(models.Model):
    code = models.CharField('Code', max_length=255, primary_key=True)
    token = models.CharField('Token', max_length=255)

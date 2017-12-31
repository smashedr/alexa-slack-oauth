from django.conf import settings
from django.conf.urls import url
from django.contrib import admin
from django.views.generic.base import RedirectView

from home import views as home

urlpatterns = [
    url(r'^$', RedirectView.as_view(
        url=settings.CONFIG.get('App', 'home_site', raw=True)
    ), name='home'),
    url(r'^favicon\.ico$', RedirectView.as_view(
        url=settings.STATIC_URL + 'images/favicon.ico'
    )),
    url(r'connect/', home.do_connect, name='connect'),
    url(r'authenticate/', home.do_login, name='authenticate'),
    url(r'token/', home.get_token, name='token'),
    url(r'success/', home.has_success, name='success'),
    url(r'error/', home.has_error, name='error'),
    url(r'^admin/', admin.site.urls, name="django_admin"),
]

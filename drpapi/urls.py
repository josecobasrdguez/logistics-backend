"""
obtain_auth_token is a view from DRF that allow to obtain a token
for authentication from user and password.
- url: api/token
- More information at: https://www.django-rest-framework.org/api-guide/authentication/
"""

from django.urls import path, re_path, register_converter
from drf_yasg.utils import swagger_auto_schema

from . import views
from rest_framework.authtoken.views import obtain_auth_token
from django.views.decorators.csrf import csrf_exempt

class DateString:
    regex = '\d{4}-\d{2}-\d{2}'

    def to_python(self, value):
        # return datetime.strptime(value, '%Y-%m-%d')
        return value

    def to_url(self, value):
        return value

register_converter(DateString, 'datestr')

urlpatterns = [
    path('user/login/', swagger_auto_schema(methods=['post'], operation_description="Login user and get token", operation_id="user_login")(csrf_exempt(obtain_auth_token)), name='token_obtain'),
    path('user/register/', swagger_auto_schema(methods=['post'], operation_description="Register user", operation_id="user_register")(views.RegisterView.as_view()), name='auth_register'),
    path('quickbooks/url/', views.token_get,  name='token_get'),
    path('quickbooks/tokenrevoke/', views.revoke,  name='revoke_tok'),
    path('quickbooks/invoices/<datestr:date>/', views.qb_invoices,  name='qb_invoices'),
    path('location/list/', views.LocationListView.as_view(),  name='location_list'),
    path('location/', views.LocationCreateView.as_view(),  name='location_create'),
    path('location/<int:id>/', views.LocationView.as_view(),  name='location_view'),
    path('driver/list/', views.DriverListView.as_view(),  name='driver_list'),
    path('driver/', views.DriverCreateView.as_view(),  name='driver_create'),
    path('driver/<int:id>/', views.DriverView.as_view(),  name='driver_view'),
    path('van/list/', views.VanListView.as_view(),  name='van_list'),
    path('van/', views.VanCreateView.as_view(),  name='van_create'),
    path('van/<int:id>/', views.VanView.as_view(),  name='van_view'),
    path('order/list/', views.OrderListView.as_view(),  name='order_list'),
    path('order/', views.OrderCreateView.as_view(),  name='order_create'),
    path('order/<int:id>/', views.OrderView.as_view(),  name='order_view'),
    path('route/list/', views.RouteListView.as_view(),  name='route_list'),
    path('route/<int:id>/', views.RouteView.as_view(),  name='route_view'),
    path('route/', views.RouteCreateView.as_view(),  name='route_create'),
    path('route/<int:id>/', views.RouteView.as_view(),  name='route_view'),
    re_path(r'^quickbooks/callback.*', views.callback,  name='callback'),
]

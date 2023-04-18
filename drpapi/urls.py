"""
obtain_auth_token is a view from DRF that allow to obtain a token
for authentication from user and password.
- url: api/token
- More information at: https://www.django-rest-framework.org/api-guide/authentication/
"""

from django.urls import path, re_path
from drf_yasg.utils import swagger_auto_schema

from . import views
from rest_framework.authtoken.views import obtain_auth_token
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('user/login/', swagger_auto_schema(methods=['post'], operation_description="Login user and get token", operation_id="user_login")(csrf_exempt(obtain_auth_token)), name='token_obtain'),
    # path('token/', views.CustomAuthToken.as_view()),
    path('user/register/', swagger_auto_schema(methods=['post'], operation_description="Register user", operation_id="user_register")(views.RegisterView.as_view()), name='auth_register'),
    # path('test/', views.MessTest.as_view(), name='test_mess'),
    # path('profilelist/', views.ProfileList.as_view(), name='profile_list'),
    # path('profileset/', views.profile_set,  name='profile_set'),
    # path('profileget/', views.profile_get,  name='profile_get'),
    path('profile/', views.ProfileView.as_view(),  name='profile_view'),
    # path('userid/', views.UserID.as_view(), name='user_id'),
    # path('userlist/', views.UserList.as_view(), name='user_list'),
    path('quickbooks/url/', views.token_get,  name='token_get'),
    path('quickbooks/tokenrevoke/', views.revoke,  name='revoke_tok'),
    path('quickbooks/invoices/', views.qb_invoices,  name='qb_invoices'),
    path('location/list/', views.location_list,  name='location_list'),
    path('location/', views.LocationView.as_view(),  name='location_view'),
    path('driver/list/', views.driver_list,  name='driver_list'),
    path('driver/', views.DriverView.as_view(),  name='driver_view'),
    path('van/list/', views.van_list,  name='van_list'),
    path('van/', views.VanView.as_view(),  name='van_view'),
    path('route/list/', views.route_list,  name='route_list'),
    path('route/<int:id>/', views.RouteView.as_view(),  name='route_view'),
    path('customerlocation/list/<int:routeid>/', views.clocation_list,  name='clocation_list'),
    path('customerlocation/', views.CustomerLocationView.as_view(),  name='clocation_view'),
    re_path(r'^quickbooks/callback.*', views.callback,  name='callback'),
]

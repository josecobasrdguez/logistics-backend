from django.contrib import admin
from django.urls import path, include, re_path
from django.conf.urls.static import static
from django.views.generic import TemplateView

from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

from config import settings

schema_view = get_schema_view(
   openapi.Info(
        title="DRP Backend",
        default_version='v0.7',
        description="DRP Backend",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="josecobas554@gmail.com"),
        license=openapi.License(name="Not defined License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    # path('admin/doc/', include('django.contrib.admindocs.urls')),
    path('admin/', admin.site.urls),
    # re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    # re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    # re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('api/', include("drpapi.urls"))
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

urlpatterns += [
    # re_path(r'^.*', TemplateView.as_view(template_name='index.html')),
    re_path(r'^.*', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]

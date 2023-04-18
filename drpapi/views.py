from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response

from drpapi.helpers import LOCATION, LOC_RESP, DRV_RESP, VAN_RESP, ROT_RESP, ROUTE_RESP, CLL_RESP, ROUTE_ID_RESP, \
    prof_resp
from drpapi.models import Profile, Location, Driver, Van, Route, CustomerLocation
from drpapi.serializers import RegisterSerializer, ProfileSerializer, UserSerializer, IdSerializer, \
    ProfileGetSerializer, DateSerializer, InvoiceSerializer, \
    UrlSerializer, VanSerializer, IdVanSerializer, LocationSerializer, IdLocationSerializer, DriverSerializer, \
    IdDriverSerializer, RouteSerializer, IdRouteSerializer, CustomerLocationSerializer, IdCustomerLocationSerializer
from rest_framework import generics, status
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny, IsAuthenticated
from intuitlib.client import AuthClient
from intuitlib.enums import Scopes
from intuitlib.exceptions import AuthClientError
from django.conf import settings

from quickbooks.exceptions import AuthorizationException


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


# class MessTest(APIView):
#
#     permission_classes = [IsAuthenticated]
#
#     def get(self, request, format=None):
#         return Response({'message': 'Success'})
#
#
# class ProfileList(generics.ListCreateAPIView):
#     queryset = Profile.objects.all()
#     serializer_class = ProfileSerializer
#     permission_classes = [IsAuthenticated]
#
#
# class UserList(generics.ListCreateAPIView):
#     queryset = User.objects.all()
#     serializer_class = UserSerializer
#     permission_classes = [IsAuthenticated]


# class ProfileAdd(generics.CreateAPIView):
#     serializer_class = ProfileSerializer
#     permission_classes = [IsAuthenticated]


# class UserID(APIView):
#     def get(self, request, format=None):
#         user = request.user
#         return Response({
#             'userid': user.pk,
#         })


# @swagger_auto_schema(methods=['post'], operation_description="Save user avatar"
#     , responses={404: 'User not found', 201: 'Created'}, request_body=ProfileGetSerializer)
# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def profile_set(request):
#     # print(request.data)
#     try:
#         profil = get_object_or_404(Profile, usr=request.user)
#     except:
#         profil = Profile()
#         profil.usr = request.user
#     profil.img = request.data['img']
#     profil.save()
#     return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)
#
#
# @swagger_auto_schema(methods=['get'], operation_description="Get user avatar"
#     , responses={404: 'User not found', 200: prof_resp})
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def profile_get(request):
#     profil = get_object_or_404(Profile, usr=request.user)
#     return Response({'img': profil.img}, status=status.HTTP_200_OK)


inv_list_resp = openapi.Response('Invoices list', InvoiceSerializer)


@swagger_auto_schema(methods=['post'], operation_description="Get invoices list from QuickBooks"
    , responses={401: 'Unautorized in QuickBooks', 200: inv_list_resp}
    , request_body=DateSerializer, operation_id="quickbooks_invoices")
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def qb_invoices(request):
    # print(request.data)
    # access_token = request.session.get('access_token', None)
    try:
        profil = get_object_or_404(Profile, usr=request.user)
    except:
        return Response({'status': '401'}, status=status.HTTP_401_UNAUTHORIZED)
    access_token = profil.access_token
    lst = []
    if access_token is not None:
        try:
            from intuitlib.client import AuthClient
            from quickbooks import QuickBooks
            from quickbooks.objects.invoice import Invoice
            from django.conf import settings
            # refresh_token = request.session.get('refresh_token', None)
            refresh_token = profil.refresh_token
            realm_id = profil.realm_id
            date = request.data['date']
            auth_client = AuthClient(
                client_id=settings.CLIENT_ID,
                client_secret=settings.CLIENT_SECRET,
                access_token=access_token,
                environment=settings.ENVIRONMENT,
                redirect_uri=settings.REDIRECT_URI,
            )
            client = QuickBooks(
                auth_client=auth_client,
                refresh_token=refresh_token,
                company_id=realm_id,
                # company_id=settings.COMPANY_ID,
            )
            # print('auth ->', request.auth)
            try:
                if date == '' or date is None:
                    invoices = Invoice.all(qb=client)
                else:
                    invoices = Invoice.filter(SeviceDate=date, qb=client)
                    # invoices = Invoice.filter(TxnDate=date, qb=client)
            except AuthorizationException:
                # print(request.auth)
                try:
                    auth_client.refresh()
                    profil.access_token = auth_client.access_token
                    profil.refresh_token = auth_client.refresh_token
                    profil.id_token = auth_client.id_token
                    profil.save()
                    resp = redirect('qb_invoices')
                    resp['Content-Type'] = 'application/json'
                    resp['Authorization'] = f'Token {request.auth}'
                    return resp
                except:
                    resp = redirect('token_get')
                    resp['Content-Type'] = 'application/json'
                    resp['Authorization'] = f'Token {request.auth}'
                    return resp
            # print(date)
            for inv in invoices:
                # txt = inv.to_json()
                dic = {}
                if inv.CustomerRef.name is not None:
                    dic['customer'] = inv.CustomerRef.name
                else:
                    dic['customer'] = ''
                # print('CustomerRef - >', dir(inv.CustomerRef))
                # print('ShipAddr - >', dir(inv.ShipAddr))
                if inv.ShipAddr is not None:
                    txt = ''
                    if len(inv.ShipAddr.Line1) > 0:
                        txt = txt + inv.ShipAddr.Line1 + ' '
                    if len(inv.ShipAddr.Line2) > 0:
                        txt = txt + inv.ShipAddr.Line2 + ' '
                    if len(inv.ShipAddr.Line3) > 0:
                        txt = txt + inv.ShipAddr.Line3 + ' '
                    if len(inv.ShipAddr.Line4) > 0:
                        txt = txt + inv.ShipAddr.Line4 + ' '
                    if len(inv.ShipAddr.Line5) > 0:
                        txt = txt + inv.ShipAddr.Line5 + ' '
                    if len(inv.ShipAddr.PostalCode) > 0:
                        txt = txt + inv.ShipAddr.PostalCode + ' '
                    if len(inv.ShipAddr.City) > 0:
                        txt = txt + inv.ShipAddr.City + ' '
                    if len(inv.ShipAddr.Country) > 0:
                        txt = txt + inv.ShipAddr.Country
                    dic['address'] = txt.rstrip(' ')
                else:
                    dic['address'] = ''
                # dic['edit'] = dic['sel'] = 0
                # txt = txt.replace('"{', '{')
                # txt = txt.replace('}"', '}')
                # txt = txt.replace('\n', '')
                # txt = txt.replace('\\', '')
                dic['date'] = date
                lst.append(dic)
                # print(txt)
            # print(lst)
        except AuthClientError as e:
            # just printing here but it can be used for retry workflows, logging, etc
            print(e.status_code)
            print(e.content)
            print(e.intuit_tid)
    # return Response({'message': 'OK'})
    return Response(lst)


url_resp = openapi.Response('URL for QuickBooks authorization', UrlSerializer)


@swagger_auto_schema(methods=['get'], operation_description="Get the URL for QuickBooks authorization",
                     responses={404: 'User not found', 200: url_resp}, operation_id="quickbooks_url")
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def token_get(request):
    auth_client = AuthClient(
        settings.CLIENT_ID,
        settings.CLIENT_SECRET,
        settings.REDIRECT_URI,
        settings.ENVIRONMENT,
    )
    url = auth_client.get_authorization_url([Scopes.ACCOUNTING])
    try:
        profil = get_object_or_404(Profile, usr=request.user)
    except:
        profil = Profile()
        profil.usr = request.user
    # request.session['state'] = auth_client.state_token
    # print('state_token ->', auth_client.state_token)
    # profil.state = auth_client.state_token[:-3]
    profil.state = auth_client.state_token
    profil.save()
    # print(url)
    # resp = HttpResponseRedirect(url)
    # resp.set_cookie('usr', request.user)
    # return redirect(url)
    return Response({'url': url}, status=status.HTTP_200_OK)


@swagger_auto_schema(methods=['get'], operation_description="Redirection URL after QuickBooks authorization",
                     responses={404: 'User not found', 200: 'Redirect'}, operation_id="quickbooks_callback")
@api_view(['GET'])
def callback(request):
    state_tok = request.GET.get('state', None)
    error = request.GET.get('error', None)

    try:
        profil = get_object_or_404(Profile, state=state_tok)
    except:
        # return HttpResponse('unauthorized', status=401)
        return redirect(f'{settings.REACT_URI}?status=401')
        # return Response({'status': '401'})

    auth_client = AuthClient(
        settings.CLIENT_ID,
        settings.CLIENT_SECRET,
        settings.REDIRECT_URI,
        settings.ENVIRONMENT,
        # state_token=request.session.get('state', None),
        state_token=state_tok,
    )

    if error == 'access_denied':
        # return redirect('app:index')
        return redirect(f'{settings.REACT_URI}?status=401')
        # return Response({'error': 'accden'})

    if state_tok is None:
        # return HttpResponseBadRequest()
        return redirect(f'{settings.REACT_URI}?status=400')
        # return Response({'error': 'badreq'})

    auth_code = request.GET.get('code', None)
    realm_id = request.GET.get('realmId', None)
    # print(realm_id)
    # request.session['realm_id'] = realm_id
    profil.realm_id = realm_id

    if auth_code is None:
        # return HttpResponseBadRequest()
        return redirect(f'{settings.REACT_URI}?status=400')
        # return Response({'error': 'badreq'})

    try:
        auth_client.get_bearer_token(auth_code, realm_id=realm_id)
        # request.session['access_token'] = auth_client.access_token
        # request.session['refresh_token'] = auth_client.refresh_token
        # request.session['id_token'] = auth_client.id_token
        profil.access_token = auth_client.access_token
        profil.refresh_token = auth_client.refresh_token
        profil.id_token = auth_client.id_token
    except AuthClientError as e:
        # just printing status_code here but it can be used for retry workflows, etc
        print(e.status_code)
        print(e.content)
        print(e.intuit_tid)
    except Exception as e:
        print(e)

    profil.save()
    # return redirect('app:connected')
    return redirect(f'{settings.REACT_URI}?status=200')
    # return Response({'status': '200'})


@swagger_auto_schema(methods=['get'], operation_description="Revoke QuickBooks token",
                     responses={404: 'User not found', 200: 'OK'}, operation_id="quickbooks_revoketoken")
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def revoke(request):
    profil = get_object_or_404(Profile, usr=request.user)
    access_token = profil.access_token
    refresh_token = profil.refresh_token
    auth_client = AuthClient(
        settings.CLIENT_ID,
        settings.CLIENT_SECRET,
        settings.REDIRECT_URI,
        settings.ENVIRONMENT,
        access_token=access_token,
        refresh_token=refresh_token,
    )
    try:
        is_revoked = auth_client.revoke()
    except AuthClientError as e:
        print(e.status_code)
        print(e.intuit_tid)
    # return HttpResponse('Revoke successful')
    return Response({'message': 'Token revoked'}, status=status.HTTP_200_OK)


# class DriverList(generics.ListCreateAPIView):
#     queryset = Driver.objects.all()
#     serializer_class = DriverSerializer
#     permission_classes = [IsAuthenticated]
#
#     def list(self, request):
#         # Note the use of `get_queryset()` instead of `self.queryset`
#         queryset = self.get_queryset()
#         queryset = queryset.filter(usr=request.user)
#         serializer = DriverSerializer(queryset, many=True)
#         return Response(serializer.data)


@swagger_auto_schema(methods=['get'], operation_description="List locations"
    , responses={404: 'Location not found', 403: 'Forbidden', 200: LOC_RESP}, operation_id="location_list")
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def location_list(request):
    l = []
    q = Location.objects.filter(usr=request.user)
    for obj in q:
        dic = {}
        dic['id'] = obj.pk
        dic['location'] = obj.location
        # dic['edit'] = 0
        l.append(dic)
    return Response(l, status=status.HTTP_200_OK)


# @swagger_auto_schema(methods=['post'], operation_description="Edit location, or insert with id 0"
#     , responses={404: 'Location not found', 403: 'Forbidden', 201: 'Created'}, request_body=IdSerializer)
# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def location_edit(request):
#     try:
#         loc = get_object_or_404(Location, pk=request.data['id'])
#         if loc.usr != request.user:
#             raise PermissionDenied
#     except:
#         loc = Location()
#         loc.usr = request.user
#     loc.location = request.data['location']
#     loc.save()
#     return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)
#
#
# @swagger_auto_schema(methods=['delete'], operation_description="Delete location"
#     , responses={404: 'Location not found', 403: 'Forbidden', 204: 'No content'}, request_body=IdSerializer)
# @api_view(['DELETE'])
# @permission_classes([IsAuthenticated])
# def location_del(request):
#     loc = get_object_or_404(Location, pk=request.data['id'])
#     if loc.usr != request.user:
#         raise PermissionDenied
#     loc.delete()
#     return Response({'message': 'OK'}, status=status.HTTP_204_NO_CONTENT)

@swagger_auto_schema(methods=['get'], operation_description="List drivers"
    , responses={404: 'User not found', 403: 'Forbidden', 200: DRV_RESP}, operation_id="driver_list")
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def driver_list(request):
    l = []
    q = Driver.objects.filter(usr=request.user)
    for obj in q:
        dic = {}
        dic['id'] = obj.pk
        dic['driver'] = obj.driver
        # dic['edit'] = 0
        l.append(dic)
    return Response(l, status=status.HTTP_200_OK)


@swagger_auto_schema(methods=['get'], operation_description="List vans"
    , responses={404: 'User not found', 403: 'Forbidden', 200: VAN_RESP}, operation_id="van_list")
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def van_list(request):
    l = []
    q = Van.objects.filter(usr=request.user)
    for obj in q:
        dic = {}
        dic['id'] = obj.pk
        dic['van'] = obj.van
        # dic['edit'] = 0
        l.append(dic)
    return Response(l, status=status.HTTP_200_OK)


class LocationView(APIView):
    """
    Location CRUD.
    """
    permission_classes = [IsAuthenticated]

    # @swagger_auto_schema(operation_description="Returns a single location"
    #     , responses={404: 'Location not found', 403: 'Forbidden', 200: LOCATION})
    # def get(self, request, format=None):
    #     """
    #     Return a single location.
    #     """
    #     loc = get_object_or_404(Location, pk=request.data['id'])
    #     if loc.usr != request.user:
    #         raise PermissionDenied
    #     return Response({'id': id, 'location': loc.location}, status=status.HTTP_200_OK)

    @swagger_auto_schema(operation_description="Create new location"
        , responses={403: 'Forbidden', 201: 'Created'}, request_body=LocationSerializer)
    def post(self, request, format=None):
        """
        Create new location.
        """
        loc = Location()
        loc.usr = request.user
        loc.location = request.data['location']
        loc.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Update an existing location"
        , responses={404: 'Location not found', 403: 'Forbidden', 201: 'Created'}, request_body=IdLocationSerializer)
    def put(self, request, format=None):
        """
        Update an existing location.
        """
        loc = get_object_or_404(Location, pk=request.data['id'])
        if loc.usr != request.user:
            raise PermissionDenied
        loc.location = request.data['location']
        loc.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Delete an existing location"
        , responses={404: 'Location not found', 403: 'Forbidden', 204: 'No content'}, request_body=IdSerializer)
    def delete(self, request, format=None):
        """
        Delete an existing location.
        """
        loc = get_object_or_404(Location, pk=request.data['id'])
        if loc.usr != request.user:
            raise PermissionDenied
        loc.delete()
        return Response({'message': 'OK'}, status=status.HTTP_204_NO_CONTENT)


class DriverView(APIView):
    """
    Driver CRUD.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(operation_description="Create new driver"
        , responses={403: 'Forbidden', 201: 'Created'}, request_body=DriverSerializer)
    def post(self, request, format=None):
        """
        Create new driver.
        """
        drv = Driver()
        drv.usr = request.user
        drv.driver = request.data['driver']
        drv.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Update an existing driver"
        , responses={404: 'Driver not found', 403: 'Forbidden', 201: 'Created'}, request_body=IdDriverSerializer)
    def put(self, request, format=None):
        """
        Update an existing driver.
        """
        drv = get_object_or_404(Driver, pk=request.data['id'])
        if drv.usr != request.user:
            raise PermissionDenied
        drv.driver = request.data['driver']
        drv.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Delete an existing driver"
        , responses={404: 'Driver not found', 403: 'Forbidden', 204: 'No content'}, request_body=IdSerializer)
    def delete(self, request, format=None):
        """
        Delete an existing driver.
        """
        drv = get_object_or_404(Driver, pk=request.data['id'])
        if drv.usr != request.user:
            raise PermissionDenied
        drv.delete()
        return Response({'message': 'OK'}, status=status.HTTP_204_NO_CONTENT)


class VanView(APIView):
    """
    Van CRUD.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(operation_description="Create new van"
        , responses={403: 'Forbidden', 201: 'Created'}, request_body=VanSerializer)
    def post(self, request, format=None):
        """
        Create new van.
        """
        van = Van()
        van.usr = request.user
        van.van = request.data['van']
        van.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Update an existing van"
        , responses={404: 'Van not found', 403: 'Forbidden', 201: 'Created'}, request_body=IdVanSerializer)
    def put(self, request, format=None):
        """
        Update an existing van.
        """
        van = get_object_or_404(Van, pk=request.data['id'])
        if van.usr != request.user:
            raise PermissionDenied
        van.van = request.data['van']
        van.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Delete an existing van"
        , responses={404: 'Van not found', 403: 'Forbidden', 204: 'No content'}, request_body=IdSerializer)
    def delete(self, request, format=None):
        """
        Delete an existing van.
        """
        van = get_object_or_404(Van, pk=request.data['id'])
        if van.usr != request.user:
            raise PermissionDenied
        van.delete()
        return Response({'message': 'OK'}, status=status.HTTP_204_NO_CONTENT)


class RouteView(APIView):
    """
    Route CRUD.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(operation_description="Returns a single route"
        , responses={404: 'Route not found', 403: 'Forbidden', 200: ROUTE_RESP}
        , operation_id="route_retrieve")
    def get(self, request, id=0, format=None):
        """
        Return a single route.
        """
        rot = get_object_or_404(Route, pk=id)
        if rot.usr != request.user:
            raise PermissionDenied
        dic = {}
        dic['id'] = rot.pk
        dic['name'] = rot.name
        if rot.driver is not None:
            dic['driver'] = {'id': rot.driver.pk, 'driver': rot.driver.driver}
        if rot.van is not None:
            dic['van'] = {'id': rot.van.pk, 'van': rot.van.van}
        if rot.startlocation is not None:
            dic['startlocation'] = {'id': rot.startlocation.pk, 'location': rot.startlocation.location}
        if rot.endlocation is not None:
            dic['endlocation'] = {'id': rot.endlocation.pk, 'location': rot.endlocation.location}
        # qs = CustomerLocation.objects.filter(route=rot)
        # dic['customerlocations'] = []
        # for clo in qs:
        #     d = {}
        #     d['route'] = clo.route
        #     d['customer'] = clo.customer
        #     d['address'] = clo.address
        #     d['priority'] = clo.priority
        #     d['payroll'] = clo.payroll
        #     dic['customerlocations'].append(d)
        return Response(dic, status=status.HTTP_200_OK)

    @swagger_auto_schema(operation_description="Create new route, use id 0"
        , responses={403: 'Forbidden', 201: ROUTE_ID_RESP}, request_body=RouteSerializer)
    def post(self, request, id=0, format=None):
        """
        Create new route.
        """
        rot = Route()
        rot.usr = request.user
        rot.name = request.data.get('name', '')
        if request.data.get('driver', 0) > 0:
            rot.driver = get_object_or_404(Driver, pk=request.data['driver'])
        if request.data.get('van', 0) > 0:
            rot.van = get_object_or_404(Van, pk=request.data['van'])
        if request.data.get('startlocation', 0) > 0:
            rot.startlocation = get_object_or_404(Location, pk=request.data['startlocation'])
        if request.data.get('endlocation', 0) > 0:
            rot.endlocation = get_object_or_404(Location, pk=request.data['endlocation'])
        rot.save()
        # for dic in request.data['customerlocations']:
        #     clo = CustomerLocation()
        #     clo.route = dic['route']
        #     clo.customer = dic['customer']
        #     clo.address = dic['address']
        #     clo.priority = dic['priority']
        #     clo.payroll = dic['payroll']
        #     clo.save()
        return Response({'id': rot.pk}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Update an existing route"
        , responses={404: 'Not found', 403: 'Forbidden', 201: 'Created'}, request_body=RouteSerializer)
    def put(self, request, id=0, format=None):
        """
        Update an existing route.
        """
        rot = get_object_or_404(Route, pk=id)
        if rot.usr != request.user:
            raise PermissionDenied
        rot.name = request.data['name']
        if request.data.get('driver', 0) > 0:
            rot.driver = get_object_or_404(Driver, pk=request.data['driver'])
        if request.data.get('van', 0) > 0:
            rot.van = get_object_or_404(Van, pk=request.data['van'])
        if request.data.get('startlocation', 0) > 0:
            rot.startlocation = get_object_or_404(Location, pk=request.data['startlocation'])
        if request.data.get('endlocation', 0) > 0:
            rot.endlocation = get_object_or_404(Location, pk=request.data['endlocation'])
        rot.save()
        # qs = CustomerLocation.objects.filter(route=rot)
        # qs.delete()
        # for dic in request.data['customerlocations']:
        #     clo = CustomerLocation()
        #     clo.route = dic['route']
        #     clo.customer = dic['customer']
        #     clo.address = dic['address']
        #     clo.priority = dic['priority']
        #     clo.payroll = dic['payroll']
        #     clo.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Delete an existing route"
        , responses={404: 'Route not found', 403: 'Forbidden', 204: 'No content'})
    def delete(self, request, id=0, format=None):
        """
        Delete an existing route.
        """
        rot = get_object_or_404(Route, pk=id)
        if rot.usr != request.user:
            raise PermissionDenied
        # qs = CustomerLocation.objects.filter(route=rot)
        # qs.delete()
        rot.delete()
        return Response({'message': 'OK'}, status=status.HTTP_204_NO_CONTENT)


@swagger_auto_schema(methods=['get'], operation_description="List route names"
    , responses={404: 'User not found', 403: 'Forbidden', 200: ROT_RESP}, operation_id="route_list")
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def route_list(request):
    l = []
    q = Route.objects.filter(usr=request.user)
    for obj in q:
        dic = {}
        dic['id'] = obj.pk
        dic['name'] = obj.name
        if obj.driver is not None:
            dic['driver'] = {'id': obj.driver.pk, 'driver': obj.driver.driver}
        if obj.van is not None:
            dic['van'] = {'id': obj.van.pk, 'van': obj.van.van}
        if obj.startlocation is not None:
            dic['startlocation'] = {'id': obj.startlocation.pk, 'location': obj.startlocation.location}
        if obj.endlocation is not None:
            dic['endlocation'] = {'id': obj.endlocation.pk, 'location': obj.endlocation.location}
        # qs = CustomerLocation.objects.filter(route=obj)
        # dic['customerlocations'] = []
        # for clo in qs:
        #     d = {}
        #     d['route'] = clo.route
        #     d['customer'] = clo.customer
        #     d['address'] = clo.address
        #     d['priority'] = clo.priority
        #     d['payroll'] = clo.payroll
        #     dic['customerlocations'].append(d)
        l.append(dic)
    return Response(l, status=status.HTTP_200_OK)


@swagger_auto_schema(methods=['get'], operation_description="List customer locations"
    , responses={404: 'Route not found', 403: 'Forbidden', 200: CLL_RESP}
    , operation_id="customerlocation_list")
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def clocation_list(request, routeid):
    rot = get_object_or_404(Route, pk=routeid)
    if rot.usr != request.user:
        raise PermissionDenied
    l = []
    q = CustomerLocation.objects.filter(route=rot)
    for obj in q:
        dic = {}
        dic['id'] = obj.pk
        dic['customer'] = obj.customer
        dic['address'] = obj.address
        dic['priority'] = obj.priority
        dic['payroll'] = obj.payroll
        dic['date'] = obj.date
        l.append(dic)
    return Response(l, status=status.HTTP_200_OK)


class CustomerLocationView(APIView):
    """
    customer location.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(operation_description="Create new customer location"
        , responses={404: 'Route not found', 403: 'Forbidden', 201: 'Created'}
        , request_body=CustomerLocationSerializer)
    def post(self, request, format=None):
        """
        Create new customer location.
        """
        rot = get_object_or_404(Route, pk=request.data['route'])
        if rot.usr != request.user:
            raise PermissionDenied
        cl = CustomerLocation()
        cl.route = rot
        cl.customer = request.data.get('customer', '')
        cl.address = request.data.get('address', '')
        cl.priority = request.data.get('priority', None)
        cl.payroll = request.data.get('payroll', None)
        cl.date = request.data.get('date', '')
        cl.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Update an existing customer location"
        , responses={404: 'Customer location not found', 403: 'Forbidden', 201: 'Created'}, request_body=IdCustomerLocationSerializer)
    def put(self, request, format=None):
        """
        Update an existing customer location.
        """
        cl = get_object_or_404(CustomerLocation, pk=request.data['id'])
        if cl.route.usr != request.user:
            raise PermissionDenied
        cl.customer = request.data.get('customer', '')
        cl.address = request.data.get('address', '')
        cl.priority = request.data.get('priority', None)
        cl.payroll = request.data.get('payroll', None)
        cl.date = request.data.get('date', '')
        cl.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(operation_description="Delete an existing customer location"
        , responses={404: 'Customer location not found', 403: 'Forbidden', 204: 'No content'}, request_body=IdSerializer)
    def delete(self, request, format=None):
        """
        Delete an existing customer location.
        """
        cl = get_object_or_404(CustomerLocation, pk=request.data['id'])
        if cl.route.usr != request.user:
            raise PermissionDenied
        cl.delete()
        return Response({'message': 'OK'}, status=status.HTTP_204_NO_CONTENT)


class ProfileView(APIView):
    """
    Profile CRUD.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(operation_description="Returns the profile data (user avatar)"
        , responses={404: 'User not found', 200: prof_resp}
        , operation_id="profile_retrieve")
    def get(self, request, format=None):
        """
        Returns the profile data (user avatar).
        """
        profil = get_object_or_404(Profile, usr=request.user)
        return Response({'img': profil.img}, status=status.HTTP_200_OK)

    @swagger_auto_schema(operation_description="Update the profile data (user avatar)"
        , responses={404: 'User not found', 201: 'Created'},
                         request_body=ProfileGetSerializer)
    def put(self, request, format=None):
        """
        Update the profile data (user avatar).
        """
        try:
            profil = get_object_or_404(Profile, usr=request.user)
        except:
            profil = Profile()
            profil.usr = request.user
        profil.img = request.data['img']
        profil.save()
        return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

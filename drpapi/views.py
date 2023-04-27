from django.http import  Http404
from django.shortcuts import redirect
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response

from drpapi.helpers import URL_RESP
from drpapi.models import Profile, Location, Driver, Van, Route, Order
from drpapi.serializers import RegisterSerializer, InvoiceSerializer, \
    UrlSerializer, VanSerializer, LocationSerializer, DriverSerializer, \
    RouteSerializer, OrderSerializer, RouteUpdateSerializer
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


inv_list_resp = openapi.Response('Invoices list', InvoiceSerializer)


@swagger_auto_schema(methods=['get'], operation_description="Get invoices list from QuickBooks, filtered by date"
    , responses={401: 'Unautorized in QuickBooks', 200: inv_list_resp}
    , operation_id="quickbooks_invoices")
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def qb_invoices(request, date):
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
            # date = request.data['date']
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
            for inv in invoices:
                # txt = inv.to_json()
                dic = {}
                if inv.CustomerRef.name is not None:
                    dic['customer'] = inv.CustomerRef.name
                else:
                    dic['customer'] = ''
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
                dic['date'] = date
                lst.append(dic)
        except AuthClientError as e:
            # just printing here but it can be used for retry workflows, logging, etc
            print(e.status_code)
            print(e.content)
            print(e.intuit_tid)
    return Response(lst)


# url_resp = openapi.Response('URL for QuickBooks authorization', UrlSerializer)


@swagger_auto_schema(methods=['get'], operation_description="Get the URL for QuickBooks authorization",
                     responses={404: 'User not found', 200: URL_RESP}, operation_id="quickbooks_url")
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
    profil.state = auth_client.state_token
    profil.save()
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
        state_token=state_tok,
    )

    if error == 'access_denied':
        return redirect(f'{settings.REACT_URI}?status=401')

    if state_tok is None:
        # return HttpResponseBadRequest()
        return redirect(f'{settings.REACT_URI}?status=400')

    auth_code = request.GET.get('code', None)
    realm_id = request.GET.get('realmId', None)
    profil.realm_id = realm_id

    if auth_code is None:
        # return HttpResponseBadRequest()
        return redirect(f'{settings.REACT_URI}?status=400')

    try:
        auth_client.get_bearer_token(auth_code, realm_id=realm_id)
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


class DriverListView(APIView):
    """
    List drivers.
    """

    @swagger_auto_schema(operation_description="List drivers"
        , responses={404: 'User not found', 403: 'Forbidden', 200: DriverSerializer(many=True)}, operation_id="driver_list")
    def get(self, request, format=None):
        q = Driver.objects.filter(usr=request.user)
        serializer = DriverSerializer(q, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LocationListView(APIView):
    """
    List locations.
    """

    @swagger_auto_schema(operation_description="List locations"
        , responses={404: 'User not found', 403: 'Forbidden', 200: LocationSerializer(many=True)}, operation_id="location_list")
    def get(self, request, format=None):
        q = Location.objects.filter(usr=request.user)
        serializer = LocationSerializer(q, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class VanListView(APIView):
    """
    List vans.
    """

    @swagger_auto_schema(operation_description="List vans"
        , responses={404: 'User not found', 403: 'Forbidden', 200: VanSerializer(many=True)}, operation_id="van_list")
    def get(self, request, format=None):
        q = Van.objects.filter(usr=request.user)
        serializer = VanSerializer(q, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RouteListView(APIView):
    """
    List routes.
    """

    @swagger_auto_schema(operation_description="List routes"
        , responses={404: 'User not found', 403: 'Forbidden', 200: RouteSerializer(many=True)}, operation_id="routes_list")
    def get(self, request, format=None):
        q = Route.objects.filter(usr=request.user)
        serializer = RouteSerializer(q, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class OrderListView(APIView):
    """
    List orders.
    """

    @swagger_auto_schema(operation_description="List orders"
        , responses={404: 'User not found', 403: 'Forbidden', 200: OrderSerializer(many=True)}, operation_id="orders_list")
    def get(self, request, format=None):
        q = Order.objects.filter(usr=request.user)
        serializer = OrderSerializer(q, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class VanCreateView(APIView):

    @swagger_auto_schema(operation_description="Create a new van"
        , responses={400: 'Bad request', 403: 'Forbidden', 201: 'Created'}, request_body=VanSerializer)
    def post(self, request, format=None):
        """
        Create a new van.
        """
        serialize = VanSerializer(data=request.data)
        if serialize.is_valid():
            serialize.save(usr=request.user)
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)


class DriverCreateView(APIView):

    @swagger_auto_schema(operation_description="Create a new driver"
        , responses={400: 'Bad request', 403: 'Forbidden', 201: 'Created'}, request_body=DriverSerializer)
    def post(self, request, format=None):
        """
        Create a new driver.
        """
        serialize = DriverSerializer(data=request.data)
        if serialize.is_valid():
            serialize.save(usr=request.user)
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)


class LocationCreateView(APIView):

    @swagger_auto_schema(operation_description="Create a new location"
        , responses={400: 'Bad request', 403: 'Forbidden', 201: 'Created'}, request_body=LocationSerializer)
    def post(self, request, format=None):
        """
        Create a new location.
        """
        serialize = LocationSerializer(data=request.data)
        if serialize.is_valid():
            serialize.save(usr=request.user)
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)


class OrderCreateView(APIView):

    @swagger_auto_schema(operation_description="Create a new order"
        , responses={400: 'Bad request', 403: 'Forbidden', 201: 'Created'}, request_body=OrderSerializer)
    def post(self, request, format=None):
        """
        Createa a new order.
        """
        serialize = OrderSerializer(data=request.data)
        if serialize.is_valid():
            serialize.save(usr=request.user)
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)


class RouteCreateView(APIView):

    @swagger_auto_schema(operation_description="Create a new route"
        , responses={400: 'Bad request', 403: 'Forbidden', 201: 'Created'}, request_body=RouteUpdateSerializer)
    def post(self, request, format=None):
        """
        Createa a new route.
        """
        serialize = RouteUpdateSerializer(data=request.data)
        if serialize.is_valid():
            serialize.save(usr=request.user)
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)


class LocationView(APIView):
    """
    Location retrieve, update & delete.
    """

    def get_object(self, request, id):
        try:
            obj = Location.objects.get(pk=id)
        except Location.DoesNotExist:
            raise Http404
        else:
            if obj.usr != request.user:
                raise PermissionDenied
            else:
                return obj

    @swagger_auto_schema(operation_description="Returns a single location"
        , responses={404: 'Location not found', 403: 'Forbidden', 200: LocationSerializer})
    def get(self, request, id, format=None):
        """
        Return a single location.
        """
        obj = self.get_object(request, id)
        serialize = LocationSerializer(obj)
        return Response(serialize.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(operation_description="Update an existing location"
        , responses={404: 'Location not found', 403: 'Forbidden', 201: 'Created'}, request_body=LocationSerializer)
    def put(self, request, id, format=None):
        """
        Update an existing location.
        """
        obj = self.get_object(request, id)
        serialize = LocationSerializer(obj, data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(operation_description="Delete an existing location"
        , responses={404: 'Location not found', 403: 'Forbidden', 204: 'No content'})
    def delete(self, request, id, format=None):
        """
        Delete an existing location.
        """
        obj = self.get_object(request, id)
        obj.delete()
        return Response({}, status=status.HTTP_204_NO_CONTENT)


class DriverView(APIView):
    """
    Driver retrieve, update & delete.
    """

    def get_object(self, request, id):
        try:
            obj = Driver.objects.get(pk=id)
        except Driver.DoesNotExist:
            raise Http404
        else:
            if obj.usr != request.user:
                raise PermissionDenied
            else:
                return obj

    @swagger_auto_schema(operation_description="Returns a single driver"
        , responses={404: 'Driver not found', 403: 'Forbidden', 200: DriverSerializer})
    def get(self, request, id, format=None):
        """
        Return a single driver.
        """
        obj = self.get_object(request, id)
        serialize = DriverSerializer(obj)
        return Response(serialize.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(operation_description="Update an existing driver"
        , responses={404: 'Driver not found', 403: 'Forbidden', 201: 'Created'}, request_body=DriverSerializer)
    def put(self, request, id, format=None):
        """
        Update an existing driver.
        """
        obj = self.get_object(request, id)
        serialize = LocationSerializer(obj, data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(operation_description="Delete an existing driver"
        , responses={404: 'Driver not found', 403: 'Forbidden', 204: 'No content'})
    def delete(self, request, id, format=None):
        """
        Delete an existing driver.
        """
        obj = self.get_object(request, id)
        obj.delete()
        return Response({}, status=status.HTTP_204_NO_CONTENT)


class VanView(APIView):
    """
    Van retrieve, update & delete.
    """

    def get_object(self, request, id):
        try:
            obj = Van.objects.get(pk=id)
        except Van.DoesNotExist:
            raise Http404
        else:
            if obj.usr != request.user:
                raise PermissionDenied
            else:
                return obj

    @swagger_auto_schema(operation_description="Returns a single van"
        , responses={404: 'Location not found', 403: 'Forbidden', 200: VanSerializer})
    def get(self, request, id, format=None):
        """
        Return a single location.
        """
        obj = self.get_object(request, id)
        serialize = VanSerializer(obj)
        return Response(serialize.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(operation_description="Update an existing van"
        , responses={404: 'Van not found', 403: 'Forbidden', 201: 'Created'}, request_body=VanSerializer)
    def put(self, request, id, format=None):
        """
        Update an existing van.
        """
        obj = self.get_object(request, id)
        serialize = VanSerializer(obj, data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(operation_description="Delete an existing van"
        , responses={404: 'Van not found', 403: 'Forbidden', 204: 'No content'})
    def delete(self, request, id, format=None):
        """
        Delete an existing van.
        """
        obj = self.get_object(request, id)
        obj.delete()
        return Response({}, status=status.HTTP_204_NO_CONTENT)


class RouteView(APIView):
    """
    Route retrieve, update & delete.
    """

    def get_object(self, request, id):
        try:
            obj = Route.objects.get(pk=id)
        except Route.DoesNotExist:
            raise Http404
        else:
            if obj.usr != request.user:
                raise PermissionDenied
            else:
                return obj

    @swagger_auto_schema(operation_description="Returns a single route"
        , responses={404: 'Route not found', 403: 'Forbidden', 200: RouteSerializer})
    def get(self, request, id, format=None):
        """
        Return a single route.
        """
        obj = self.get_object(request, id)
        serialize = RouteSerializer(obj)
        return Response(serialize.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(operation_description="Update an existing route"
        , responses={404: 'Route not found', 403: 'Forbidden', 201: 'Created'}, request_body=RouteUpdateSerializer)
    def put(self, request, id, format=None):
        """
        Update an existing route.
        """
        obj = self.get_object(request, id)
        serialize = RouteUpdateSerializer(obj, data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(operation_description="Delete an existing route"
        , responses={404: 'Route not found', 403: 'Forbidden', 204: 'No content'})
    def delete(self, request, id, format=None):
        """
        Delete an existing route.
        """
        obj = self.get_object(request, id)
        obj.delete()
        return Response({}, status=status.HTTP_204_NO_CONTENT)


class OrderView(APIView):
    """
    Order retrieve, update & delete.
    """

    def get_object(self, request, id):
        try:
            obj = Order.objects.get(pk=id)
        except Order.DoesNotExist:
            raise Http404
        else:
            if obj.usr != request.user:
                raise PermissionDenied
            else:
                return obj

    @swagger_auto_schema(operation_description="Returns a single order"
        , responses={404: 'Order not found', 403: 'Forbidden', 200: OrderSerializer})
    def get(self, request, id, format=None):
        """
        Return a single order.
        """
        obj = self.get_object(request, id)
        serialize = OrderSerializer(obj)
        return Response(serialize.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(operation_description="Update an existing order"
        , responses={404: 'Order not found', 403: 'Forbidden', 201: 'Created'}, request_body=OrderSerializer)
    def put(self, request, id, format=None):
        """
        Update an existing order.
        """
        obj = self.get_object(request, id)
        serialize = OrderSerializer(obj, data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response({}, status=status.HTTP_201_CREATED)
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(operation_description="Delete an existing order"
        , responses={404: 'Order not found', 403: 'Forbidden', 204: 'No content'})
    def delete(self, request, id, format=None):
        """
        Delete an existing order.
        """
        obj = self.get_object(request, id)
        obj.delete()
        return Response({}, status=status.HTTP_204_NO_CONTENT)


# class ProfileView(APIView):
#     """
#     Profile CRUD.
#     """
#     permission_classes = [IsAuthenticated]
#
#     @swagger_auto_schema(operation_description="Returns the profile data (user avatar)"
#         , responses={404: 'User not found', 200: prof_resp}
#         , operation_id="profile_retrieve")
#     def get(self, request, format=None):
#         """
#         Returns the profile data (user avatar).
#         """
#         profil = get_object_or_404(Profile, usr=request.user)
#         return Response({'img': profil.img}, status=status.HTTP_200_OK)
#
#     @swagger_auto_schema(operation_description="Update the profile data (user avatar)"
#         , responses={404: 'User not found', 201: 'Created'},
#                          request_body=ProfileGetSerializer)
#     def put(self, request, format=None):
#         """
#         Update the profile data (user avatar).
#         """
#         try:
#             profil = get_object_or_404(Profile, usr=request.user)
#         except:
#             profil = Profile()
#             profil.usr = request.user
#         profil.img = request.data['img']
#         profil.save()
#         return Response({'message': 'OK'}, status=status.HTTP_201_CREATED)

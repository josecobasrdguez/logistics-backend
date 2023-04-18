
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from drpapi.models import Profile, Location, CustomerLocation, Route


class IdSerializer(serializers.Serializer):
    id = serializers.IntegerField(min_value=0)


class DriverSerializer(serializers.Serializer):
    driver = serializers.CharField(allow_blank=True)


class IdDriverSerializer(serializers.Serializer):
    id = serializers.IntegerField(min_value=0)
    driver = serializers.CharField(allow_blank=True)


class LocationSerializer(serializers.Serializer):
    location = serializers.CharField(allow_blank=True)


class IdLocationSerializer(serializers.Serializer):
    id = serializers.IntegerField(min_value=0)
    location = serializers.CharField(allow_blank=True)


class VanSerializer(serializers.Serializer):
    van = serializers.CharField(allow_blank=True)


class IdVanSerializer(serializers.Serializer):
    id = serializers.IntegerField(min_value=0)
    van = serializers.CharField(allow_blank=True)


class ProfileGetSerializer(serializers.Serializer):
    img = serializers.CharField(allow_blank=True)


class DateSerializer(serializers.Serializer):
    date = serializers.DateField()


class InvoiceSerializer(serializers.Serializer):
    customer = serializers.CharField(allow_blank=True)
    address = serializers.CharField(allow_blank=True)


class UrlSerializer(serializers.Serializer):
    url = serializers.URLField()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username']
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

#
# class LocationSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Location
#         fields = ['id', 'location']


class CustomerLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerLocation
        fields = ['customer', 'address', 'priority', 'payroll']


class RouteSerializer(serializers.ModelSerializer):
    # customerlocations = CustomerLocationSerializer(many=True, read_only=True)

    class Meta:
        model = Route
        fields = ['name', 'driver', 'van', 'startlocation', 'endlocation']
        # fields = ['name', 'driver', 'van', 'startlocation', 'endlocation', 'customerlocations']


class IdRouteSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(min_value=0)

    class Meta:
        model = Route
        fields = ['id', 'name', 'driver', 'van', 'startlocation', 'endlocation']
        # fields = ['id', 'name', 'driver', 'van', 'startlocation', 'endlocation', 'customerlocations']


class CustomerLocationSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomerLocation
        fields = ['route', 'customer', 'address', 'priority', 'payroll']


class IdCustomerLocationSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(min_value=0)

    class Meta:
        model = CustomerLocation
        fields = ['id', 'customer', 'address', 'priority', 'payroll']
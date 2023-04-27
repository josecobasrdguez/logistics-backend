
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from drpapi.models import Profile, Location, Route, Driver, Van, Order


class DriverSerializer(serializers.ModelSerializer):
    """
    Serializer for Driver model
    """

    class Meta:
        model = Driver
        fields = ('id', 'driver')


class LocationSerializer(serializers.ModelSerializer):
    """
    Serializer for Location model
    """

    class Meta:
        model = Location
        fields = ('id', 'location')


class VanSerializer(serializers.ModelSerializer):
    """
    Serializer for Van model
    """

    class Meta:
        model = Van
        fields = ('id', 'van')


# class ProfileGetSerializer(serializers.Serializer):
#     img = serializers.CharField(allow_blank=True)


class InvoiceSerializer(serializers.Serializer):
    customer = serializers.CharField(allow_blank=True)
    address = serializers.CharField(allow_blank=True)
    date = serializers.CharField(allow_blank=True)


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


class CustomerLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['customer', 'address', 'priority', 'payroll']


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['id', 'route', 'customer', 'address', 'priority', 'payroll', 'date']


class RouteSerializer(serializers.ModelSerializer):
    driver = DriverSerializer(many=False, read_only=True)
    van = VanSerializer(many=False, read_only=True)
    startlocation = LocationSerializer(many=False, read_only=True)
    endlocation = LocationSerializer(many=False, read_only=True)
    orders = OrderSerializer(many=True, read_only=True, source='order_set')

    class Meta:
        model = Route
        fields = ['id', 'name', 'driver', 'van', 'startlocation', 'endlocation', 'orders']


class RouteUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = Route
        fields = ['id', 'name', 'driver', 'van', 'startlocation', 'endlocation']


class CustomerLocationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Order
        fields = ['route', 'customer', 'address', 'priority', 'payroll']

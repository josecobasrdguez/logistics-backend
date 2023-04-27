from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
from django.db import models
from config import settings


class Profile(models.Model):
    """
    Model for store user data
    """

    usr = models.OneToOneField(User, models.CASCADE
                               , default='user_null', verbose_name='System user')
    img = models.TextField(verbose_name='Image', blank=True, null=True)
    state = models.TextField(blank=True, null=True)
    realm_id = models.TextField(blank=True, null=True)
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    id_token = models.TextField(blank=True, null=True)


class Location(models.Model):
    """
    Model for store locations
    """
    usr = models.ForeignKey(User, on_delete=models.CASCADE)
    location = models.CharField(max_length=255, verbose_name='Location')


class Driver(models.Model):
    """
    Model for store drivers
    """
    usr = models.ForeignKey(User, on_delete=models.CASCADE)
    driver = models.CharField(max_length=255, verbose_name='Driver')


class Van(models.Model):
    """
    Model for store vans
    """
    usr = models.ForeignKey(User, on_delete=models.CASCADE)
    van = models.CharField(max_length=255, verbose_name='Van')


class Route(models.Model):
    """
    Model for store routes
    """
    usr = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, verbose_name='Name', default='')
    driver = models.ForeignKey(Driver, on_delete=models.SET_NULL, blank=True, null=True)
    van = models.ForeignKey(Van, on_delete=models.SET_NULL, blank=True, null=True)
    startlocation = models.ForeignKey(Location, on_delete=models.SET_NULL, related_name='startloc', blank=True, null=True)
    endlocation = models.ForeignKey(Location, on_delete=models.SET_NULL, related_name='endloc', blank=True, null=True)


class Order(models.Model):
    """
    Model for store customer locations
    """
    usr = models.ForeignKey(User, on_delete=models.CASCADE)
    route = models.ForeignKey(Route, on_delete=models.CASCADE)
    customer = models.CharField(max_length=255, verbose_name='Customer')
    address = models.CharField(max_length=255, verbose_name='Address')
    priority = models.IntegerField(blank=True, null=True, validators=[MinValueValidator(1)])
    payroll = models.DecimalField(blank=True, null=True, max_digits=15, decimal_places=2)
    date = models.CharField(max_length=255)

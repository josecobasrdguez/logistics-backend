from drf_yasg import openapi

from drpapi.serializers import LocationSerializer, ProfileGetSerializer

LOCATION = '''
Example JSON

{
    "id": "1", 
    "location": "location name 1",
}'''

# LOC_RESP = openapi.Response('Locations list', LocationSerializer)

LOC_RESP = '''
Example JSON

[
    {
        "id": "1", 
        "location": "location name 1",
    },
    {
        "id": "2", 
        "location": "location name 2",
    },
    ...
]'''

DRV_RESP = '''
Example JSON

[
    {
        "id": "1", 
        "driver": "driver name 1",
    },
    {
        "id": "2", 
        "driver": "driver name 2",
    },
    ...
]'''

VAN_RESP = '''
Example JSON

[
    {
        "id": "1", 
        "van": "van name 1",
    },
    {
        "id": "2", 
        "van": "van name 2",
    },
    ...
]'''

ROT_RESP = '''
Example JSON

[
    {
        "id": 1, 
        "name": "route name 1",
        "driver": {"id": driver id 1, "driver": "driver name 1"},
        "van": {"id": van id 1, "van": "van name 1"},
        "startlocation": {"id": location id 1, "location": "location name 1"},
        "endlocation": {"id": location id 2, "location": "location name 2"},        
    },    
    ...
]'''

ROUTE_RESP = '''
Example JSON

{
    "id": 1, 
    "name": "route name 1",
    "driver": driver id 1,
    "van": van id 1,
    "startlocation": location id 1,
    "endlocation": location id 2,    
}   
'''

ROUTE_ID_RESP = '''
Example JSON

{
    "id": 1 
}   
'''


CLL_RESP = '''
Example JSON

[
    {"id": 1, "customer": "customer 1", "address": "address 1", "priority": 1, "payroll": 23, "date": "2023-04-02", },
    {"id": 2, "customer": "customer 2", "address": "address 2", "priority": 2, "payroll": 35, "date": "2023-04-02", },
    ...
]
    '''

CUSL_RESP = '''
Example JSON

{
    "id": 1, 
    "customer": "customer 1", 
    "address": "address 1", 
    "priority": 1, 
    "payroll": 23,
    "date": "2023-04-02",      
}   
'''

# route_id = openapi.Parameter('route_id', in_=openapi.IN_QUERY,
#                            type=openapi.TYPE_INTEGER)

prof_resp = openapi.Response('Image in a text field', ProfileGetSerializer)


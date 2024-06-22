import key_config as keys
import boto3 
from boto3 import resource

from boto3.dynamodb.conditions import Key, Attr


demo_table =resource(
    'dynamodb',
    aws_access_key_id="",
    aws_secret_access_key=""
).Table('userdata')

name = "nivas"
email = "2100030001@kluniversity.in"
password = "1234"
demo_table.put_item(
        Item={
        'name': name,
        'email': email,
        'password': password
            }
        )
msg = "Registration Complete. Please Login to your account !"
    

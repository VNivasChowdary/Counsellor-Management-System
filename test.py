import key_config as keys
import boto3 
from boto3 import resource

from boto3.dynamodb.conditions import Key, Attr


demo_table =resource(
    'dynamodb',
    aws_access_key_id="AKIAQ3EGSMC5X6KNJSAQ",
    aws_secret_access_key="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"
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
    
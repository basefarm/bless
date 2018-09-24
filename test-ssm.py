#!/usr/local/bin/python3

import boto3
from botocore.exceptions import ClientError

def put(name, value, keyid):
    ssm = boto3.client('ssm')
    ssm.put_parameter(
        Name=name,
        Value=value,
        Type='SecureString',
        KeyId=keyid)

def get(name):
    ssm = boto3.client('ssm')
    try:
        r = ssm.get_parameter(
            Name=name,
            WithDecryption=True)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ParameterNotFound':
            return None
        else:
            raise
    return r['Parameter']['Value']

name='/spc-prod/Bless/1/bless-key'
secret='My secret text'

value = get(name)
if value is None:
    print("Name not found. Create it...")
    put(name, secret, 'alias/BLESS-eu-west-1')
    value = get(name)
    if value is None:
        print("Something went wrong, after put still no value found.")
    else:
        print("Found value: '{0}'".format(value))
else:
    print("Found value: '{0}'".format(value))

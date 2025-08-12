#!/usr/bin/env python

import io
import json
import os
import re
import logging
import threading
from base64 import b64decode
import boto3
import paramiko
from botocore.exceptions import ClientError

# Logging
logging.basicConfig()
logging.getLogger("paramiko").setLevel(logging.ERROR)

# Env Vars
ENCRYPTED = os.environ['SFTP_PASS']
S3_BUCKET = os.getenv('S3_BUCKET')
SFTP_USER = os.getenv('SFTP_USER')
SFTP_HOST = os.getenv('SFTP_HOST')
SFTP_PATH = os.getenv('SFTP_PATH')
S3_PREFIX = os.getenv('S3_PREFIX', '')
FILTER_PATTERN = os.getenv('FILTER_PATTERN')
AWS_LAMBDA_FUNCTION_NAME = os.getenv('AWS_LAMBDA_FUNCTION_NAME')
SFTP_SECRET_NAME = os.getenv('SFTP_SECRET_NAME')
REGION_NAME = os.getenv('AWS_REGION', 'us-east-1')

# Password Decrypt
DECRYPTED = boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(ENCRYPTED),
    EncryptionContext={'LambdaFunctionName': AWS_LAMBDA_FUNCTION_NAME}
)['Plaintext'].decode('utf-8')

# Exception Handler
def exception_handler(e):
    """Format exception as Lambda proxy response."""
    return {
        "statusCode": 400,
        "body": str(e)
    }

# Secrets Manager: Get Private Key
def get_secret():
    """Retrieve SFTP private key from AWS Secrets Manager."""
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=REGION_NAME
    )
    try:
        response = client.get_secret_value(SecretId=SFTP_SECRET_NAME)
        secret = json.loads(response['SecretString'])
        return str(secret['ProdSftpPrivateKey'])
    except ClientError as e:
        raise e

# SFTP Client with Multi-factor Authentication
def multifactor_auth_sftp_client(host, port, username, key, password):
    """
    Flow below establishes SFTP connection using both private key and password. Modify to align with your target server's auth flow.
    """
    try:
        transport = paramiko.Transport((host, port))
        transport.connect()
        transport.auth_publickey(username, key)

        password_auth_event = threading.Event()
        password_auth_handler = paramiko.auth_handler.AuthHandler(transport)
        transport.auth_handler = password_auth_handler
        transport.lock.acquire()
        password_auth_handler.auth_event = password_auth_event
        password_auth_handler.auth_method = 'password'
        password_auth_handler.username = username
        password_auth_handler.password = password

        userauth_message = paramiko.message.Message()
        userauth_message.add_string('ssh-userauth')
        userauth_message.rewind()
        password_auth_handler._parse_service_accept(userauth_message)
        transport.lock.release()
        password_auth_handler.wait_for_response(password_auth_event)

        if transport.is_authenticated():
            print(f'Authentication successful to {host}!')
            return transport.open_sftp_client()
        else:
            msg = f'SFTP connection failed to {host}: {str(e)}'
            print(msg)
            return exception_handler(msg)
    except (AttributeError, paramiko.AuthenticationException, paramiko.BadHostKeyException) as e:
        msg = f'SFTP connection failed to {host}: {str(e)}'
        return exception_handler(msg)

# Lambda Handler
def lambda_handler(event, context):
    """
    Lambda entry point: Download files from SFTP and upload to S3.
    """
    s3_client = boto3.client('s3')
    sftp_key = get_secret()
    key_buffer = io.StringIO()
    key_buffer.write(sftp_key)
    key_buffer.seek(0)

    file_count = 0
    ignore_count = 0
    ignore_list = []
    upload_list = []

    pem_key = paramiko.RSAKey.from_private_key(key_buffer)
    sftp_client = multifactor_auth_sftp_client(
        SFTP_HOST, 22, SFTP_USER, pem_key, str(DECRYPTED)
    )

    if not hasattr(sftp_client, 'listdir'):
        # If sftp_client is an error response
        return sftp_client

    try:
        file_list = sftp_client.listdir(SFTP_PATH)
        if file_list:
            for filename in file_list:
                if re.search(FILTER_PATTERN, filename):
                    print(filename)
                    file_with_path = f"{SFTP_PATH}/{filename}"
                    temp_file = f"/tmp/{filename}"
                    s3_file = f"{S3_PREFIX}{filename}"
                    sftp_client.get(file_with_path, temp_file)
                    s3_client.upload_file(temp_file, S3_BUCKET, s3_file)
                    file_count += 1
                    upload_list.append(filename)
                else:
                    ignore_count += 1
                    ignore_list.append(filename)
            msg = {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "message": "Completed!",
                    "uploaded_file_count": file_count,
                    "ignored_file_count": ignore_count,
                    "uploaded_file_list": upload_list,
                    "ignored_file_list": ignore_list
                }
            }
            print(msg)
            sftp_client.close()
            return msg
        else:
            msg = {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "message": "No new files found on server",
                    "uploaded_file_count": file_count,
                    "ignored_file_count": ignore_count,
                    "uploaded_file_list": upload_list,
                    "ignored_file_list": ignore_list
                }
            }
            print(msg)
            sftp_client.close()
            return msg
    except Exception as err:
        msg = f'Encountered an error during channel session: {str(err)}'
        return exception_handler(msg)
    finally:
        pass
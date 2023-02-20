
import logging
import json
import hmac
import hashlib
import re
import datetime

import boto3
import base64
from botocore.exceptions import ClientError

from urllib.parse import unquote
from pull_secret import get_secret

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

events = boto3.client('events')

def process(content, event_type):
    entries = [
            {
                "Source": "lambda.github.webhook",
                "DetailType": "GitHub Webhook",
                "Detail": json.dumps(content),
                "Detail-Type": event_type

            }
        ]
    event_response = events.put_events(Entries=entries)


def lambda_handler(event, context):
    logger.info("Lambda execution starting up...")
    
    if not authenticate(event):
        logger.error('Unauthorized attempt')
        return {
            'statusCode': 401,
            'body': json.dumps('Unauthorized')
        }

    logger.info('Request successfully authorized')

    process(json.loads(event['body'], check_event_type(event)))

    return {
        'statusCode': 204
    }


def authenticate(event):
    incoming_signature = re.sub(r'^sha1=', '', event['headers']['X-Hub-Signature'])
    incoming_payload = json.dumps(json.loads(unquote(re.sub(r'^payload=', '', event['body']))), separators=(',', ':'))
    
    calculated_signature = calculate_signature(json.loads(get_secret())["webhash"], incoming_payload.encode('utf-8'))
    
    return hmac.compare_digest(incoming_signature, calculated_signature)

def calculate_signature(github_signature, githhub_payload):
    signature_bytes = github_signature.encode("utf-8")
    digest = hmac.new(key=signature_bytes, msg=githhub_payload, digestmod=hashlib.sha1)
    signature = digest.hexdigest()
    return signature

def check_event_type(event):
    raise event['headers']['X-GitHub-Event']
    
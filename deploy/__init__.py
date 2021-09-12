#!/usr/bin/env python3

from logging import handlers
from flask import Flask, request
import logging, datetime, hmac, hashlib
from logging.handlers import RotatingFileHandler
import secrets

app = Flask(__name__)

# Logging utility - Limit size to 100KiB per file and keep 3 files
# This size is used since this should only be hit infreqeuntly, so logs should be small
logger = logging.getLogger("IEEE-Deploy")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("/var/log/IEEE-Deploy/status.log", maxBytes=100*1024, backupCount=3)
logger.addHandler(handler)

# All logging formatting is Python2.7

@app.route('/deploy', methods=['POST'])
def deploy():
    time_recv = datetime.datetime.now()
    if request.method == 'POST':
        # Check if headers exist
        if "host" in request.headers and "X-GitHub-Delivery" in request.headers and "X-GitHub-Event" in request.headers and "X-Hub-Signature-256" in request.headers:
            # Validate the webhook
            signature = hmac.new(secrets.token, request.data, hashlib.sha256).hexdigest()
            if signature != request.headers["X-Hub-Signature-256"][7:]:
                logger.warn('%s -- Invalid GitHub WebHook Signature' % (time_recv))
                return ''
            
            logger.info('%s -- Recieved GitHub WebHook %s' % (time_recv, request.headers['X-GitHub-Delivery']))
            body = request.json
            
            
            return '<p>Recieved %s to %s</p>' % (body['events'][0],body['repository']['name'])
        else: # Not a valid WebHook
            logger.info('%s -- Not a GitHub WebHook or Improper Headers' % (time_recv))
            return ''
    else:
        # This branch should never be hit, but just in case
        logger.error('%s -- Flask allowed non-POST request' % (time_recv))
        return ''
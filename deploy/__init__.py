#!/usr/bin/env python3

from flask import Flask, request
import logging, datetime, hmac, hashlib
import secrets

app = Flask(__name__)

# Logging utility
logging.basicConfig(filename='IEEE-Deploy.log', level=logging.INFO)

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
                logging.warn('%s -- Invalid GitHub WebHook Signature' % (time_recv))
                return ''
            
            logging.info('%s -- Recieved GitHub WebHook %s' % (time_recv, request.headers['X-GitHub-Delivery']))
            body = request.json
            with open('test', 'w') as file:
                file.write(body)
            
            return '<p>Deployed!</p>'
        else: # Not a valid WebHook
            logging.info('%s -- Not a GitHub WebHook or Improper Headers' % (time_recv))
            return ''
    else:
        # This branch should never be hit, but just in case
        logging.error('%s -- Flask allowed non-POST request' % (time_recv))
        return ''
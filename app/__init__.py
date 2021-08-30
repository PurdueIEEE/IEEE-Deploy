#!/usr/bin/env python3

from flask import Flask, request
import logging, datetime

app = Flask(__name__)

# Logging utility
logging.basicConfig(filename='IEEE-Deploy.log', level=logging.INFO)

@app.route('/deploy', methods=['POST'])
def deploy():
    time_recv = datetime.datetime.now()
    if request.method == 'POST':
        # Validate Headers
        if "host" in request.headers and "X-GitHub-Delivery" in request.headers and "X-GitHub-Event" in request.headers and "X-Hub-Signature-256" in request.headers:
            logging.info(f'{time_recv} -- Recieved WebHook {request.headers["X-GitHub-Delivery"]}')
            
            return '<p>Deployed!</p>'
        else: # Not a valid WebHook
            logging.info(f'{time_recv} -- Not a GitHub WebHook or Improper Headers')
            return ''
    else:
        # This branch should never be hit, but just in case
        logging.error(f'{time_recv} -- Flask allowed non-POST request')
        return ''
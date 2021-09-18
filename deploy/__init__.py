'''
Copyright 2021 Hadi Ahmed

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

from flask import Flask, request
import logging, datetime, hmac, hashlib, subprocess
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

# Hardcode certain repos only
# Change the filepath mappings if they change
repos = {'PurdueIEEE/IEEE-Website':'/srv/web/IEEE-Website', 'PurdueIEEE/boilerbooks':'/srv/web/money'}

@app.route('/deploy', methods=['POST'])
def deploy():
    time_recv = datetime.datetime.now()
    if request.method == 'POST':
        # Check if headers exist
        if "host" in request.headers and "X-GitHub-Delivery" in request.headers and "X-GitHub-Event" in request.headers and "X-Hub-Signature-256" in request.headers:
            # Validate the webhook
            signature = hmac.new(secrets.token, request.data, hashlib.sha256).hexdigest()
            if signature != request.headers["X-Hub-Signature-256"][7:]:
                logger.warn('%s -- %s -- Invalid GitHub WebHook Signature' % (time_recv, request.remote_addr))
                return '', 403 # Forbidden
            
            body = request.json
            logger.info('%s -- %s -- Recieved GitHub WebHook %s for repo %s' % (time_recv, request.remote_addr, request.headers['X-GitHub-Delivery'], body['repository']['full_name']))

            # Check mapping table first
            if body['repository']['full_name'] in repos:
                good=True
                # Attempt a git pull for the directory
                try:
                    subprocess.check_output(['git', '-C', repos[body['repository']['full_name']], 'pull'])
                    logger.info('%s -- %s -- Succeed to git pull %s' % (time_recv, request.remote_addr,  body['repository']['full_name']))
                except subprocess.CalledProcessError as e:
                    # Something went wrong
                    logger.error('%s -- %s -- Failed to git pull %s: %s' % (time_recv, request.remote_addr, body['repository']['full_name'], e.output))
                    good=False
                finally:
                    # Spit a response back
                    return '<p>Recieved push to %s, %s<p>' % (body['repository']['full_name'], "Succeed to git pull" if good else "Failed to git pull"), 200 if good else 500 # Good or server error
            else:
                # Not in mapping table
                logger.warn('%s -- %s -- Repository %s is not included in mapping table' % (time_recv, request.remote_addr, body['repository']['full_name']))
                return '<p>Recieved push to %s, not in mapping table</p>' % (body['repository']['full_name']), 400 # Bad Request

        else: # Not a valid WebHook
            logger.info('%s -- %s -- Not a GitHub WebHook or Improper Headers' % (time_recv, request.remote_addr))
            return '', 404 # Not Found
    else:
        # This branch should never be hit, but just in case
        logger.error('%s -- %s -- Flask allowed non-POST request' % (time_recv, request.remote_addr))
        return '', 404 # Not Found
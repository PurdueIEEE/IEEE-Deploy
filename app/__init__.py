#!/usr/bin/env python3

from flask import Flask, request

app = Flask(__name__)

@app.route('/deploy', methods=['POST'])
def deploy():
    if request.method == 'POST':
        return '<p>Deployed!</p>'
    else:
        # This branch should never be hit, but just in case
        return ''
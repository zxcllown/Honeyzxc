#Libraries
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for

#Logging Format
logging_format = logging.Formatter('%(asctime)s %(message)s')

#HTTP Logger
http_logger = logging.getLogger('HTTP Logger')
http_logger.setLevel(logging.INFO)
http_handler = RotatingFileHandler('logs/http_audits.log', maxBytes=20000, backupCount=5)
http_handler.setFormatter(logging_format)
http_logger.addHandler(http_handler)

#Baseline honeypot
def web_honeypot(input_username = "admin", input_password = "password"):

    app = Flask(__name__)

    @app.route('/')

    def index():
        return render_template('wp-admin.html')

    @app.route('/wp-admin-login', methods=['POST'])

    def login_page():
        username = request.form['username']
        password = request.form['password']

        ip_address = request.remote_addr
        http_logger.info(f'Client with IP address: {ip_address} entered username: {username} and password: {password}')
        if username == input_username and password == input_password:
            return 'Nice Shot'
        else:
            return 'Wrong username or password'

    return app

def run_web_honeypot(port=5000,input_username = "admin", input_password = "password"):
    run_web_honeypot_app = web_honeypot(input_username, input_password)
    run_web_honeypot_app.run(debug=True, port=port, host='0.0.0.0')

    return run_web_honeypot_app

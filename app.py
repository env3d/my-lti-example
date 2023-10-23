
"""
Basic wraper LTI tool to allow launch and update grade book

Modified from https://github.com/dmitry-viskov/pylti1.3-flask-example
"""

import traceback
import datetime
import os
import random
import pprint
import json
import jwt
import logging
logging.getLogger().setLevel(logging.INFO)

from tempfile import mkdtemp
from flask import Flask, jsonify, request, render_template, url_for, Response, session
from flask_cors import CORS
from flask_caching import Cache
from werkzeug.exceptions import Forbidden
from pylti1p3.contrib.flask import FlaskOIDCLogin, FlaskMessageLaunch, FlaskRequest, FlaskCacheDataStorage
from pylti1p3.deep_link_resource import DeepLinkResource
from pylti1p3.grade import Grade

#from pylti1p3.tool_config import ToolConfJsonFile
#from json_file import ToolConfJsonFile
from pylti1p3.tool_config import ToolConfDict

lms_settings = {
    "https://elearn.capu.ca": {
        "auth_login_url": "https://elearn.capu.ca/mod/lti/auth.php",
        "auth_token_url": "https://elearn.capu.ca/mod/lti/token.php",
        "key_set_url": "https://elearn.capu.ca/mod/lti/certs.php",
        "private_key_file": "private.key",
        "public_key_file": "public.key"
    },
    "https://sandbox.moodledemo.net": {
        "auth_login_url": "https://sandbox.moodledemo.net/mod/lti/auth.php",
        "auth_token_url": "https://sandbox.moodledemo.net/mod/lti/token.php",
        "key_set_url": "https://sandbox.moodledemo.net/mod/lti/certs.php",        
        "private_key_file": "private.key",
        "public_key_file": "public.key"       
    }
}

def get_tool_config( merge_config ):
    """ pick the lms settings and add client_id and deployment_id """

    iss = merge_config['iss']
    client_id = merge_config["client_id"]
    settings = lms_settings[iss]
    settings["client_id"] = client_id
    settings["deployment_ids"] = [ merge_config["lti_deployment_id"] ]

    tool_conf = ToolConfDict({ iss: settings })

    with open(settings['public_key_file'], encoding="utf-8") as prf:
        tool_conf.set_public_key(iss, prf.read(), client_id=client_id)
        
    with open(settings['private_key_file'], encoding="utf-8") as prf:
        tool_conf.set_private_key(iss, prf.read(), client_id=client_id)

    return tool_conf

class ReverseProxied:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)


app = Flask('My LTI Wrapper')
app.wsgi_app = ReverseProxied(app.wsgi_app)
CORS(app)

config = {
    "DEBUG": True,
    "ENV": "development",
    "CACHE_TYPE": "simple",
    "CACHE_DEFAULT_TIMEOUT": 600,
    "SECRET_KEY": "replace-me",
    "SESSION_TYPE": "filesystem",
    "SESSION_FILE_DIR": mkdtemp(),
    "SESSION_COOKIE_NAME": "pylti1p3-flask-app-sessionid",
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SECURE": False,   # should be True in case of HTTPS usage (production)
    "SESSION_COOKIE_SAMESITE": None,  # should be 'None' in case of HTTPS usage (production)
    "DEBUG_TB_INTERCEPT_REDIRECTS": False
}
app.config.from_mapping(config)
cache = Cache(app)

class ExtendedFlaskMessageLaunch(FlaskMessageLaunch):
        
    def validate_nonce(self):
        """
        Probably it is bug on "https://lti-ri.imsglobal.org":
        site passes invalid "nonce" value during deep links launch.
        Because of this in case of iss == http://imsglobal.org just skip nonce validation.

        """
        return self

    
def get_lti_config_path():
    return os.path.join(app.root_path, 'config.json')


def get_launch_data_storage():
    return FlaskCacheDataStorage(cache)

@app.route('/login/', methods=['GET', 'POST'])
def login():
    logging.info("/login data:")
    logging.info(request.values)
    
    tool_conf = get_tool_config(request.values)    
    
    launch_data_storage = get_launch_data_storage()

    flask_request = FlaskRequest()
    target_link_uri = flask_request.get_param('target_link_uri')
    if not target_link_uri:
        raise Exception('Missing "target_link_uri" param')
    
    oidc_login = FlaskOIDCLogin(flask_request, tool_conf, launch_data_storage=launch_data_storage)
    return oidc_login\
        .enable_check_cookies()\
        .redirect(target_link_uri)

@app.route('/launch/', methods=['POST'])
def launch():
    logging.info('/launch')

    flask_request = FlaskRequest()
    
    client_info = jwt.decode(request.values['id_token'], options={"verify_signature": False})
    
    override = { 'iss': client_info['iss'],
                 'client_id': client_info["aud"],
                 'lti_deployment_id': client_info["https://purl.imsglobal.org/spec/lti/claim/deployment_id"]}

    tool_conf = get_tool_config( override )
    
    launch_data_storage = get_launch_data_storage()    

    message_launch = ExtendedFlaskMessageLaunch(flask_request, tool_conf, launch_data_storage=launch_data_storage)
    
    message_launch_data = message_launch.get_launch_data()

    launch_id = message_launch.get_launch_id()
    
    try:        
        #redirect_url = message_launch_data["https://purl.imsglobal.org/spec/lti/claim/custom"]["redirect"]
        redirect_url = message_launch_data["https://purl.imsglobal.org/spec/lti/claim/resource_link"]["description"]
        tool_base = message_launch_data["https://purl.imsglobal.org/spec/lti/claim/target_link_uri"]
        if len(redirect_url.strip()) == 0:
            raise Exception('redirect_url not provided')
        destination_url = f'{redirect_url}#launch_id={launch_id}&tool_base={tool_base}'
        return Response(f'Redirecting to <a href={destination_url}>{destination_url}</a>',
                        status=301,
                        headers={'location': f'{destination_url}'})
    except Exception as err:    
        output = '\n'.join([
            f'Launch successful, please note the details below\n',
            f'launch_id (useful for calling the rest of api): {launch_id}\n',
            f'launch_id will be fowarded to another app using HTML fragment if you provide',
            f'the redirection url in the activitiy description\n',
            f'{json.dumps(message_launch_data, indent=2)}'
        ])
        # host = request.headers['X-Forwarded-Host'] if 'X-Forwarded-Host' in request.headers else request.headers['Host']    
        # req = f"https://{host}/lti/api/score/{message_launch.get_launch_id()}/{random_score}/"    
        # random_score = random.randint(0,99)    
        # return f'<a href={req}>{req}</a>'        
        return Response(response=output, headers={ 'content-type': 'text/plain' })

@app.route('/launch/api/score/<launch_id>/<score>/', methods=['GET'])
@app.route('/launch/api/score/<launch_id>/<score>/<comment>', methods=['GET'])
def score(launch_id, score, comment=None):
    logging.info(f"API: Score, with launch id: {launch_id}")

    client_info = cache.get(launch_id)

    override = { 'iss': client_info['iss'],
                 'client_id': client_info["aud"],
                 'lti_deployment_id': client_info["https://purl.imsglobal.org/spec/lti/claim/deployment_id"]}
    
    tool_conf = get_tool_config( override )

    flask_request = FlaskRequest()    
    launch_data_storage = get_launch_data_storage()
    
    #tool_conf = ToolConfJsonFile(get_lti_config_path(), override=override)    

    message_launch = ExtendedFlaskMessageLaunch.from_cache(launch_id, flask_request, tool_conf,
                                                           launch_data_storage=launch_data_storage)

    resource_link_id = message_launch.get_launch_data() \
        .get('https://purl.imsglobal.org/spec/lti/claim/resource_link', {}).get('id')

    if not message_launch.has_ags():
        raise Forbidden("Don't have grades!")

    sub = message_launch.get_launch_data().get('sub')
    timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
    score = int(score)
    
    grades = message_launch.get_ags()
    sc = Grade()
    sc.set_score_given(score) \
        .set_score_maximum(100) \
        .set_timestamp(timestamp) \
        .set_activity_progress('Completed') \
        .set_grading_progress('FullyGraded') \
        .set_user_id(sub)
    if comment != None:
        sc.set_comment(comment)

    try:
        result=grades.put_grade(sc)
        return jsonify({'success': True, 'result': result.get('body')})
    except Exception as err:
        logging.error(err)
        return jsonify({'success': False})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9001)

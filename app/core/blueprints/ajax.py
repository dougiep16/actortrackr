from flask import Flask
from flask import render_template
from flask import Blueprint
from flask import flash
from flask import request
from flask import redirect
from flask import jsonify
from flask import Markup
from flask import g

import functools
import json
import hashlib
import logging
import os
import sys
import time
import uuid
from datetime import datetime
from operator import itemgetter
from urllib.parse import quote_plus

from config.settings import *
from core.forms import forms
from app import log, get_es, get_mysql
from utils.elasticsearch import *
from utils.functions import *

#blue print def
ajax_blueprint = Blueprint('ajax', __name__, url_prefix="/ajax")
logger_prefix = "ajax.py:"

#dynamic select populator
@ajax_blueprint.route("/fetch/<_type>/<value>", methods = ['GET'])
def fetch(_type, value):
    logging_prefix = logger_prefix + "fetch({},{}) - ".format(_type,value)
    log.info(logging_prefix + "Starting")

    r = fetch_child_data(_type,value)
    return jsonify(r), 200


#dynamic select populator
@ajax_blueprint.route("/related/<_type>", methods = ['GET'])
@ajax_blueprint.route("/related/<_type>/", methods = ['GET'])
def populate_related_elements(_type):
    logging_prefix = logger_prefix + "populate_related_elements({}) - ".format(_type)
    log.info(logging_prefix + "Starting")

    r = fetch_related_elements(_type)
    return jsonify(r), 200
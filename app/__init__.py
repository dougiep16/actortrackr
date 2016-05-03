#!/usr/bin/env python3.4
if __name__ == "__main__":
    import os
    import sys

    TOP_DIR = os.path.dirname(os.path.realpath(__file__))

    CONFIG_PATH= TOP_DIR+"/config"
    LIB_PATH= TOP_DIR+"/lib"
    APP_PATH = TOP_DIR+"/app"

    sys.path.insert(0, TOP_DIR)
    sys.path.insert(0, CONFIG_PATH)
    sys.path.insert(0, LIB_PATH)
    sys.path.insert(0, APP_PATH)

from config.settings import *

import logging
from logging.handlers import TimedRotatingFileHandler
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
 
# add a rotating handler
handler = TimedRotatingFileHandler(LOG_FILE, when='d', interval=1, backupCount=5) #creates daily logs for 5 days
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)

try:
    from flask import Flask
    from flask import render_template
    from flask import flash
    from flask import request
    from flask import redirect
    from flask import jsonify
    from flask import Markup
    from flask import g
except Exception as e:
    print("Error: {}\nFlask is not installed, try 'pip install flask'".format(e))
    exit(1)

try:
    from elasticsearch import Elasticsearch
    from elasticsearch import exceptions
except:
    print("Error: {}\nElasticsearch library is not installed, try 'pip install elasticsearch'".format(e))
    exit(1)


try:
    import pymysql
    from pymysql.cursors import DictCursor
except Exception as e:
    print("Error: {}\PyMySQL library is not installed, try 'pip install PyMySQL'".format(e))
    exit(1)

#if you want a lot of elastic logs uncomment this section
'''
es_logger = logging.getLogger('elasticsearch')
es_logger.propagate = False
es_logger.setLevel(logging.DEBUG)
es_logger_handler=logging.StreamHandler()
es_logger.addHandler(es_logger_handler)

es_tracer = logging.getLogger('elasticsearch.trace')
es_tracer.propagate = False
es_tracer.setLevel(logging.INFO)
es_tracer_handler=logging.StreamHandler()
es_tracer.addHandler(es_tracer_handler)
'''

app = Flask(__name__)
app.secret_key = "Fgtqweds5ywDJsQW87uQnL"

def get_es():
    try:
        db = getattr(g, 'es', None)
        if db is None:
            db = g.es = Elasticsearch(ES_HOSTS)
    except RuntimeError as rte:
        db = Elasticsearch(ES_HOSTS)
    
    return db

def get_mysql():
    try:
        db = getattr(g, 'mysql', None)
        if db is None:
            db = g.mysql =  pymysql.connect(user=MYSQL_USER,passwd=MYSQL_PASSWD,db=MYSQL_DB, cursorclass=DictCursor)
    except RuntimeError as rte:
        db = g.mysql =  pymysql.connect(user=MYSQL_USER,passwd=MYSQL_PASSWD,db=MYSQL_DB, cursorclass=DictCursor)
    
    return db

@app.before_request
def before_request():
    g.es      =     get_es()
    g.mysql   =     get_mysql()

@app.teardown_request
def teardown_request(exception):
    get_mysql().close()
    pass

from core.blueprints.actor import actor_blueprint
from core.blueprints.admin import admin_blueprint
from core.blueprints.ajax import ajax_blueprint
from core.blueprints.index import index_blueprint
from core.blueprints.report import report_blueprint
from core.blueprints.ttp import ttp_blueprint
from core.blueprints.user import user_blueprint

app.register_blueprint(actor_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(ajax_blueprint)
app.register_blueprint(index_blueprint)
app.register_blueprint(report_blueprint)
app.register_blueprint(ttp_blueprint)
app.register_blueprint(user_blueprint)



if __name__ == "__main__":

    #start flask
    app.run(
        host = '0.0.0.0',
        port = 8888,
        threaded=True,
        debug=True
        )

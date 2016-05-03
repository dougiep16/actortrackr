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
import requests
import sys
import time
import uuid
from datetime import datetime
from pymysql.cursors import DictCursor
from operator import itemgetter
from urllib.parse import unquote_plus, quote_plus

from config.settings import *
from core.decorators import authentication
from core.forms import forms
from app import log, get_es, get_mysql
from utils.elasticsearch import *
from utils.functions import *

#blue print def
admin_blueprint = Blueprint('admin', __name__, url_prefix="/admin")
logger_prefix = "admin.py:"

@admin_blueprint.route("/user/<action>/<value>/<user_id>/<user_c>", methods = ['GET'])
@admin_blueprint.route("/user/<action>/<value>/<user_id>/<user_c>/", methods = ['GET'])
@authentication.access(authentication.ADMIN)
def edit_user_permissions(action,value,user_id,user_c):
    logging_prefix = logger_prefix + "edit_user_permissions({},{},{},{}) - ".format(action,value,user_id,user_c)
    log.info(logging_prefix + "Starting") 

    action_column_map = {}
    action_column_map['approve'] = "approved"
    action_column_map['write_perm'] = "write_permission"
    action_column_map['delete_perm'] = "delete_permission"
    action_column_map['admin_perm'] = "admin"

    success = 1
    try:
        #make sure the value is valid
        if value not in ["0","1"]:
            raise Exception("Invald value: {}".format(value))

        #make sure the action is valid    
        try:
            column = action_column_map[action]
        except Exception as f:
            log.warning(logging_prefix + "Action '{}' not found in action_column_map".format(action))
            raise f

        #check the hash
        if user_c == sha256(SALTS['user'], str(user_id)):

            #if action is approve, emails need to be sent
            if action == "approve":
                conn = get_mysql().cursor(DictCursor)
                conn.execute("SELECT name, email FROM users WHERE id = %s", (user_id,))
                user = conn.fetchone()
                conn.close()

                if value == "1":
                    log.info(logging_prefix + "Setting approved=1 for user {}".format(user_id))
                    sendAccountApprovedEmail(user['email'])
                else:
                    log.info(logging_prefix + "Setting approved=0 for user {}".format(user_id))
                    sendAccountDisapprovedEmail(user['email'])

            #now update the desired setting
            conn = get_mysql().cursor()
            conn.execute("UPDATE users SET "+column+" = %s WHERE id = %s", (value,user_id))
            get_mysql().commit()
            conn.close()
            log.info(logging_prefix + "Successfully update {} to {} for user id {}".format(column,value,user_id))

        else:
            log.warning(logging_prefix + "Hash mismatch {} {}".format(user_id, user_c))
    except Exception as e:
        success = 0
        error = "There was an error completing your request. Details: {}".format(e)
        log.exception(logging_prefix + error)

    return jsonify({ "success" : success, "new_value" : value })


'''
Admin Pages
'''

@admin_blueprint.route("/", methods = ['GET','POST'])
@admin_blueprint.route("", methods = ['GET','POST'])
@authentication.access(authentication.ADMIN)
def main():
    logging_prefix = logger_prefix + "main() - "
    log.info(logging_prefix + "Starting")

    try:
        conn=get_mysql().cursor(DictCursor)
        conn.execute("SELECT id, name, email, company, email_verified, approved, write_permission, delete_permission, admin FROM users ORDER BY created DESC")

        users = conn.fetchall()
        for user in users:
            user['id_hash'] = sha256( SALTS['user'], str(user['id']) )

        conn.close()

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)


    return render_template("admin.html",
                        page_title="Admin",
                        url = "",
                        users=users
            )
@admin_blueprint.route("/choices", methods = ['GET','POST'])
@admin_blueprint.route("/choices/", methods = ['GET','POST'])
@authentication.access(authentication.ADMIN)
def choices():
    logging_prefix = logger_prefix + "choices() - "
    log.info(logging_prefix + "Starting")

    simple_choices = None
    try:

        body = {
            "query" : {
                "match_all" : {}
            },
            "size" : 1000
        }

        results = get_es().search(ES_PREFIX + 'threat_actor_simple', 'data', body)

        parsed_results = []
        for r in results['hits']['hits']:
            d = {}
            d['type'] = r['_source']['type']
            d['value'] = r['_source']['value']
            d['id'] = r['_id']

            #determine how many actor profiles use this value

            query_string = None
            if d['type'] == "classification":
                query_string = "type:\"" + escape(d['value']) + "\""
            elif d['type'] == "communication":
                query_string = "communication_address.type:\"" + escape(d['value']) + "\""
            elif d['type'] == "country":
                query_string = "country_affiliation:\"" + escape(d['value']) + "\" origin:\"" + escape(d['value']) + "\""

            if query_string:
                body = {
                    "query" : {
                        "query_string" : {
                            "query" : query_string
                        }
                    },
                    "size" : 0
                }

                count = get_es().search(ES_PREFIX + 'threat_actors', 'actor', body)

                d['count'] = count['hits']['total']
                d['q'] = quote_plus(query_string)
            else:
                d['count'] = "-"
                d['q'] = ""

            parsed_results.append(d)

        simple_choices = multikeysort(parsed_results, ['type', 'value'])

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    return render_template("admin_choices.html",
                        page_title="Admin",
                        simple_choices = simple_choices
            )



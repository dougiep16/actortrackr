from flask import Flask
from flask import render_template
from flask import Blueprint
from flask import flash
from flask import request
from flask import redirect
from flask import jsonify
from flask import Markup
from flask import session
from flask import abort
from flask import g

import functools
import json
import hashlib
import logging
import math
import os
import sys
import time
import uuid
from datetime import datetime
from functools import wraps 
from pymysql.cursors import DictCursor
from operator import itemgetter
from urllib.parse import quote_plus

from config.settings import *
from core.forms import forms
from app import log, get_es, get_mysql
from utils.elasticsearch import *
from utils.functions import *

logger_prefix = "authentication.py:"

PUBLIC = 0
WRITE = 1
DELETE = 2
ADMIN = 3

def access(access_level=PUBLIC):
    logging_prefix = logger_prefix + "access() - "
    
    def decorated(f):
        @wraps(f) 

        def wrapped(*args, **kwargs):

            r = quote_plus(request.url)
            try:
                if access_level != PUBLIC:
                    if 'logged_in' not in session:
                        flash("You must log in to continue", 'danger')
                        return redirect("/user/login/?r={}".format(r), code=307)
                    elif not session['logged_in']:
                        flash("You must log in to continue", 'danger')
                        return redirect("/user/login/?r={}".format(r), code=307)
                    elif session['expires'] < math.ceil(time.time()) and SESSION_EXPIRE != -1:
                        flash("Your session has expired, log in below to continue", 'danger')
                        return redirect("/user/logout/?r={}".format(r), code=307)
                    
                    
                    #since the user is logged in requery the database for their current permissons
                    if 'id' not in session:
                        log.error(logging_prefix - "ID not in session: {}".format(session))
                        flash("Theres an issue with your session, please log in again. Error 001.", 'danger')
                        return redirect("/user/login/?r={}".format(r), code=307)

                    conn = get_mysql().cursor(DictCursor)
                    conn.execute("SELECT email_verified, approved, write_permission, delete_permission, admin FROM users WHERE id = %s", (session['id'],))
                    user = conn.fetchone()
                    conn.close()

                    if not user:
                        log.error(logging_prefix - "User not found: {}".format(session))
                        flash("Theres an issue with your session, please log in again. Error 002.", 'danger')
                        return redirect("/user/logout/?r={}".format(r), code=307)

                    if user['email_verified'] != 1:
                        flash("Your email address has not been verified yet", 'danger')
                        return redirect("/user/logout/?r={}".format(r), code=307)

                    session['approved']     =   (user['approved'] == 1)
                    session['write']        =   (user['write_permission'] == 1)
                    session['delete']       =   (user['delete_permission'] == 1)
                    session['admin']        =   (user['admin'] == 1)

                    #now that we know this user is logged in set the expiration to much later
                    session['expires'] = math.ceil(time.time()) + SESSION_EXPIRE

                    #compare the users current access to the access level needed for this page
                    if not session['approved']:
                        #if read is not set, the users account has been disabled
                        flash("Your account has been disabled", 'danger')
                        return redirect("/user/logout/?r={}".format(r), code=307)


                    elif access_level == WRITE and not session['write']:
                        return render_template("error_403.html")
                    elif access_level == DELETE and not session['delete']:
                        return render_template("error_403.html")
                    elif access_level == ADMIN and not session['admin']:
                        return render_template("error_403.html")

            except Exception as e:
                log.exception("Error performing user authentication")
                flash("Your account could not be verified, please log in again", 'danger')
                return redirect("/user/logout/?r={}".format(r), code=307)

            return f(*args, **kwargs)

        return wrapped
    return decorated
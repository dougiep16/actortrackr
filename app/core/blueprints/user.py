from flask import Flask
from flask import render_template
from flask import Blueprint
from flask import flash
from flask import request
from flask import redirect
from flask import jsonify
from flask import Markup
from flask import session
from flask import g

import functools
import json
import hashlib
import logging
import math
import os
import requests
import sys
import time
import uuid
from datetime import datetime
from datetime import timedelta
from pymysql.cursors import DictCursor
from operator import itemgetter
from urllib.parse import unquote_plus, quote_plus

from config.settings import *
from core.forms import forms
from app import log, get_es, get_mysql
from utils.elasticsearch import *
from utils.functions import *

user_blueprint = Blueprint('user', __name__, url_prefix="/user")
logger_prefix = "user.py:"

'''
User Pages
'''

@user_blueprint.route("/register", methods = ['GET','POST'])
@user_blueprint.route("/register/", methods = ['GET','POST']) 
def register():
    logging_prefix = logger_prefix + "register() - "
    log.info(logging_prefix + "Starting")
    try:

        form = forms.registerForm(request.form)
        search_form = forms.searchForm()

        if request.method == 'POST':

            #verify captcha
            perform_validate = True
            try:
                if RECAPTCHA_ENABLED:
                    captcha_value = request.form['g-recaptcha-response']
                    r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
                            'secret': RECAPTCHA_PRIVATE_KEY,
                            'response': request.form['g-recaptcha-response']
                        })
                    r_json = json.loads(r.text)

                    if not r_json['success']:
                        flash("Bots are not allowed",'danger')
                        perform_validate = False

            except Exception as s:
                log.exception(logging_prefix + "Error preforming captcha validation")
                raise s

            if perform_validate and form.validate():
                log.info(logging_prefix + "Sign up Detected")

                #get data from form
                name = form.user_name.data
                email = form.user_email.data 
                password = form.user_password.data
                company = form.user_company.data
                reason = form.user_reason.data

                #create the necessary hashes
                salted_password = sha256(SALTS['user'],password)
                verification_hash = sha256(SALTS['email_verification'], email)

                #insert data into mysql
                insert = "INSERT INTO users (email, password, name, company, justification, email_verified, verification_hash) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                values = (email, salted_password, name, company, reason, 0, verification_hash)
                log.info(logging_prefix + "Adding new user {}".format(values))

                try:
                    conn=get_mysql().cursor()
                    conn.execute(insert, values)
                    get_mysql().commit()
                    conn.close()
                except Exception as s:
                    conn.close()
                    raise s

                #email the user to verify email
                try:
                    sendAccountVerificationEmail(email, verification_hash)
                except Exception as s:
                    log.exception(logging_prefix + "Unable to send email to {} with verification_hash {}".format(email, verification_hash))
                    raise s

                flash("You have been registered. A verification email with an actviation link has been sent to {} from noreply_ctig@lgscout.com".format(email),'success')
            else:

                print(form.errors)
        else:
            pass

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)


    return render_template("register.html",
                        page_title="Register",
                        form=form,
                        recaptcha_enabled=RECAPTCHA_ENABLED,
                        recaptcha_key=RECAPTCHA_PUBLIC_KEY,
                        search_form=search_form
            )

@user_blueprint.route("/issues", methods = ['GET'])
@user_blueprint.route("/issues/", methods = ['GET']) 
def issues():
    search_form = forms.searchForm()

    return render_template("issues.html",
                        page_title="Trouble Logging In",
                        search_form=search_form
            )

@user_blueprint.route("/password/request_reset", methods = ['GET','POST'])
@user_blueprint.route("/password/request_reset/", methods = ['GET','POST']) 
def password_request_reset():
    logging_prefix = logger_prefix + "password_request_reset() - "
    log.info(logging_prefix + "Starting")
    try:
        form = forms.userEmailForm(request.form)
        search_form = forms.searchForm()

        if request.method == 'POST':
            if form.validate():
                email = form.user_email.data

                #make sure the email exists in the system
                conn=get_mysql().cursor(DictCursor)
                conn.execute("SELECT id FROM users WHERE email = %s", (email,))
                user = conn.fetchone()
                conn.close()

                if user:
                    expiration_ts = int(time.time()) + 3600
                    password_reset_hash = sha256(SALTS['user'],str(user['id']) + str(expiration_ts))

                    #set this value in the database, so it can be expired after the password is changed
                    conn=get_mysql().cursor(DictCursor)
                    conn.execute("INSERT INTO password_reset_hashes (user_id,hash) VALUES (%s,%s)", (user['id'],password_reset_hash))
                    get_mysql().commit()
                    conn.close()

                    password_reset_link = "/user/password/reset/{}/{}/{}/".format(user['id'],expiration_ts,password_reset_hash)

                    sendPasswordResetEmail(email, password_reset_link)

                    flash("An email has been sent to '{}' with a link to reset your password. This link expires in 1 hour.".format(email),'success')
                else:
                    flash("The email you entered was not found", "danger")

            else:
                print(form.errors)

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    return render_template("password_reset.html",
                        page_title="Reset Your Password",
                        page_type="REQUEST",
                        form=form,
                        search_form=search_form
            )

@user_blueprint.route("/password/reset/<user_id>/<expiration_ts>/<password_reset_hash>", methods = ['GET','POST'])
@user_blueprint.route("/password/reset/<user_id>/<expiration_ts>/<password_reset_hash>/", methods = ['GET','POST']) 
def password_reset(user_id=None, expiration_ts=None, password_reset_hash=None):
    logging_prefix = logger_prefix + "password_reset({},{},{}) - ".format(user_id, expiration_ts, password_reset_hash)
    log.info(logging_prefix + "Starting")
    
    try:
        if sha256(SALTS['user'],user_id+expiration_ts) != password_reset_hash:
            flash("There was an error completing your request", 'danger')
            return redirect("/user/password/request_reset/")

        form = forms.passwordPerformResetForm(request.form)
        search_form = forms.searchForm()

        now = int(time.time())

        if now > int(expiration_ts): # passworD1!
            flash("This link has expired", 'danger')
            return redirect("/user/password/request_reset/")

        conn=get_mysql().cursor(DictCursor)
        conn.execute("SELECT COUNT(*) as count FROM password_reset_hashes WHERE hash = %s AND user_id = %s", (password_reset_hash,user_id))
        result = conn.fetchone()
        conn.close()

        if not result:
            flash("This link has expired", 'danger')
            return redirect("/user/password/request_reset/")

        if result['count'] == 0:
            flash("This link has expired", 'danger')
            return redirect("/user/password/request_reset/")

        if request.method == 'POST':
            if form.validate():
                password = form.user_password.data
                salted_password = sha256(SALTS['user'],password)

                conn=get_mysql().cursor()
                conn.execute("UPDATE users SET password = %s WHERE id = %s", (salted_password,user_id))
                conn.execute("DELETE FROM password_reset_hashes WHERE user_id = %s", (user_id,))
                get_mysql().commit()
                conn.close()

                flash("Your password has been updated", "success")
                return redirect("/user/login")
            else:
                print(form.errors)

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    log.info(logging_prefix + "Rendering")
    return render_template("password_reset.html",
                        page_title="Reset Your Password",
                        page_type="PERFORM",
                        form=form,
                        search_form=search_form
            )

@user_blueprint.route("/login", methods = ['GET','POST'])
@user_blueprint.route("/login/", methods = ['GET','POST'])
def login():
    logging_prefix = logger_prefix + "login() - "
    log.info(logging_prefix + "Starting")

    try:
        form = forms.loginForm(request.form)
        search_form = forms.searchForm()

        if request.method == 'POST':
            if form.validate():
                email = form.user_email.data 
                password = form.user_password.data

                hashed_password = sha256(SALTS['user'], password)

                conn=get_mysql().cursor(DictCursor)
                #since email is unique
                conn.execute("SELECT id, password, name, email_verified, approved, write_permission, delete_permission, admin FROM users WHERE email = %s", (email,))
                user = conn.fetchone()
                

                if user:
            
                    if user['password'] == hashed_password:
                        #we have found a valid user

                        if user['email_verified']==0:
                            #the user has not verified their email address
                            flash("Your email address has not been verified. Click here if you did not receive a verification email", "danger")

                        elif user['approved']==0:
                            #the user has not been approved, or their access has been disapproved
                            flash("Your account has been approved yet, you will receive an email when your account has been approved", "danger")

                        else:
                            #woohoo successful login, set up session variables
                            session['logged_in']    =   True
                            session['id']           =   user['id']
                            session['name']         =   user['name']
                            session['email']        =   email
                            session['approved']     =   (user['approved'] == 1)
                            session['write']        =   (user['write_permission'] == 1)
                            session['delete']       =   (user['delete_permission'] == 1)
                            session['admin']        =   (user['admin'] == 1)
                            session['expires']      =   math.ceil(time.time()) + SESSION_EXPIRE
                                                                            #now + 10 minutes of inactivity
                                                                            #each time this user loads a page
                                                                            #the expiration time gets now + 10m

                            #update last login timestamp
                            conn=get_mysql().cursor(DictCursor)
                            conn.execute("UPDATE users SET last_login=%s WHERE id = %s", (datetime.now(), user['id']))
                            get_mysql().commit()
                            conn.close()

                            flash("You have been logged in", "success")

                            if request.args.get("r"):
                                return redirect(request.args.get("r"))
                            else:
                                return redirect("/") 
                    else:
                        log.warning(logging_prefix + "Invalid login attempt for {}".format(email))
                        flash("The username or password is incorrect", "danger")
                else:
                    log.warning(logging_prefix + "Invalid login attempt for {}".format(email))
                    flash("The username or password is incorrect", "danger")
            else:
                print(form.errors)

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    return render_template("login.html",
                        page_title="Login",
                        form=form,
                        search_form=search_form
            ) 

@user_blueprint.route("/logout", methods = ['GET'])
@user_blueprint.route("/logout/", methods = ['GET'])
def logout():
    logging_prefix = logger_prefix + "logout() - "
    log.info(logging_prefix + "Starting")

    session['logged_in']    =   False
    session['id']           =   None
    session['name']         =   None
    session['email']        =   None
    session['approved']     =   None
    session['write']        =   None
    session['delete']       =   None
    session['admin']        =   None
    session['expires']      =   None

    flash("You have been logged out", 'success')

    if request.args.get("r"):
        return redirect("/user/login/?r={}".format(quote_plus(request.args.get("r"))))
    else:
        return redirect("/user/login/", code=307) 


@user_blueprint.route("/verify/<email>/<verification_hash>", methods = ['GET'])
@user_blueprint.route("/verify/<email>/<verification_hash>/", methods = ['GET']) 
def verify(email, verification_hash):
    logging_prefix = logger_prefix + "verify() - "
    log.info(logging_prefix + "Starting")

    email = unquote_plus(email)

    print(email)
    print(verification_hash)

    try:
        conn=get_mysql().cursor(DictCursor)
        conn.execute("SELECT id, email, name, company, justification FROM users WHERE verification_hash = %s", (verification_hash,))
        r = conn.fetchone()
        if not r:
            log.error(logging_prefix + "User with email '{}' was not found".format(email))
            flash("Your user was not found, try registering again",'danger')
        elif r['email'] == email:
            log.info(logging_prefix + "Successful validation of {}".format(email))
            flash("Your email address have been verified, you will not be able to log in until you get approved by the Site Admin",'success')

            #update the database marking this user active
            user_id = r['id']
            conn.execute("UPDATE users SET email_verified=1 WHERE id = %s", (user_id,))
            get_mysql().commit()

            #id, email, name, company
            sendNewUserToApproveEmail(r['id'], r['email'],r['name'],r['company'],r['justification'])
        else:
            log.warning(logging_prefix + "Unsuccessful validation of {}".format(email))
            flash("We were unable to verify your account",'danger')

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)
    finally:
        conn.close()

    return redirect("/", code=307)

@user_blueprint.route("/reverify", methods = ['GET','POST'])
@user_blueprint.route("/reverify/", methods = ['GET',"POST"]) 
def reverify():
    logging_prefix = logger_prefix + "reverify() - "
    log.info(logging_prefix + "Starting")
    try:
        form = forms.userEmailForm(request.form)
        search_form = forms.searchForm()

        if request.method == 'POST':
            if form.validate():
                email = form.user_email.data

                #make sure the email exists in the system
                conn=get_mysql().cursor(DictCursor)
                conn.execute("SELECT verification_hash FROM users WHERE email = %s", (email,))
                user = conn.fetchone()
                conn.close()

                if user:
                    sendAccountVerificationEmail(email, user['verification_hash'])

                    flash("A verification email has been sent to '{}' with a link to verify your account.".format(email),'success')
                else:
                    flash("The email you entered was not found", "danger")

            else:
                print(form.errors)

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    return render_template("account_reverify.html",
                        page_title="Verify Account",
                        form=form,
                        search_form=search_form
            )






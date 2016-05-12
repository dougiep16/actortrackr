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

#email imports
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config.settings import *
from core.forms import forms
from app import log
from utils.elasticsearch import *
from utils.functions import *

logger_prefix = "functions.py:"

def sha256(salt, s):
    s = salt + s
    hash_object = hashlib.sha256(s.encode('utf-8'))
    return hash_object.hexdigest()

def print_tpx(tpx):
    print(json.dumps(tpx, sort_keys=True, indent=4, separators=(',', ': ')))

def cmp(a, b):
    return (a > b) - (a < b) 

def multikeysort(items, columns):
    from operator import itemgetter
    comparers = [ ((itemgetter(col[1:].strip()), -1) if col.startswith('-') else (itemgetter(col.strip()), 1)) for col in columns]
    def comparer(left, right):
        for fn, mult in comparers:
            result = cmp(fn(left), fn(right))
            if result:
                return mult * result
        else:
            return 0
    return sorted(items, key=functools.cmp_to_key(comparer))

def sendAccountVerificationEmail(email, verification_hash):
    to      = [ email, ]
    sender  = EMAIL_SENDER
    subject = "{}: Account Activation".format(APPLICATION_NAME)
    body    = 'Thank you for registering for the {} {}. To verify your email address, click <a href="{}/user/verify/{}/{}">here</a>.<br/><br/>If you were not expecting this email, please send an email to ctig@lookingglasscyber.com.'.format(APPLICATION_ORG, APPLICATION_NAME, APPLICATION_DOMAIN, quote_plus(quote_plus(email)), verification_hash)

    sendHTMLEmail(to, sender, subject, body)

def sendNewUserToApproveEmail(user_id, user_email, user_name, user_company, user_justification):
    to      = EMAIL_ADDRESSES
    sender  = EMAIL_SENDER
    subject = "{}: New Verified User".format(APPLICATION_NAME)
    body    = 'A new user has signed up and verified their email. They can be approved on the Admin page.<br/><br/>Name: {}<br/>Email: {}<br/>Company: {}<br/>Justification: {}'.format(user_name, user_email, user_company, user_justification)

    sendHTMLEmail(to, sender, subject, body)


def sendAccountApprovedEmail(user_email):
    to      = [ user_email, ]
    sender  = EMAIL_SENDER
    subject = "{}: Account Approved".format(APPLICATION_NAME)
    body    = 'Your account for the {} {} has been approved<br/><br/>Click <a href="{}/user/login/">here</a> to log in.'.format(APPLICATION_ORG, APPLICATION_NAME, APPLICATION_DOMAIN)

    sendHTMLEmail(to, sender, subject, body)

def sendAccountDisapprovedEmail(user_email):
    to      = [ user_email, ]
    sender  = EMAIL_SENDER
    subject = "{}: Account Access Removed".format(APPLICATION_NAME)
    body    = 'Your access to the {} {} has been removed<br/><br/>If you feel this has been done in error, contact <a href="mailto:ctig@lookingglasscyber.com">ctig@lookingglasscyber.com</a>'.format(APPLICATION_ORG, APPLICATION_NAME)

    sendHTMLEmail(to, sender, subject, body)

def sendPasswordResetEmail(user_email, reset_link):
    to      = [ user_email, ]
    sender  = EMAIL_SENDER
    subject = "{}: Password Reset".format(APPLICATION_NAME)
    body    = 'To reset your password, click <a href="{}{}">here</a>'.format(APPLICATION_DOMAIN, reset_link)

    sendHTMLEmail(to, sender, subject, body)


def sendCustomEmail(user_email, subject, body):
    to      = [ user_email, ]
    sender  = EMAIL_SENDER

    sendPlainTextEmail(to, sender, subject, body)

'''
Email Senders
'''

def sendPlainTextEmail(to, sender, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(to)
    s = smtplib.SMTP('localhost')
    s.sendmail(sender, to, msg.as_string())
    s.quit()

    print("Email sent")

def sendHTMLEmail(to, sender, subject, body):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(to)

    msgbody = MIMEText(body, 'html')
    msg.attach(msgbody)

    s = smtplib.SMTP('localhost')
    s.sendmail(sender, to, msg.as_string())
    s.quit()

    print("Email sent")
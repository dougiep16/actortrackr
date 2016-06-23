
from flask import Flask
from flask import render_template
from flask import Blueprint
from flask import flash
from flask import request
from flask import redirect
from flask import make_response
from flask import jsonify
from flask import Markup
from flask import g

from elasticsearch import TransportError
from elasticsearch.helpers import scan

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
from core.decorators import authentication
from core.forms import forms
from app import log, get_es, get_mysql


#blue print def
index_blueprint = Blueprint('index', __name__, url_prefix="")
logger_prefix = "index.py:"


@index_blueprint.route("/about", methods = ['GET'])
@authentication.access(authentication.PUBLIC)
def about():
    search_form = forms.searchForm()

    return render_template("about.html",
                        page_title="About",
                        search_form = search_form
            )

@index_blueprint.route("/contact", methods = ['GET'])
@authentication.access(authentication.PUBLIC)
def contact():
    search_form = forms.searchForm()

    return render_template("contact.html",
                        page_title="Contact",
                        search_form = search_form
            )

@index_blueprint.route("/", methods = ['GET','POST'])
@authentication.access(authentication.PUBLIC)
def index():
    logging_prefix = logger_prefix + "index() - "
    log.info(logging_prefix + "Loading home page")
    
    form = forms.searchForm(request.form)
    error = None
    url = "/"
    query_string_url = ""
    try:
        #this is the default query for actors in ES, i'd imagine this will be recently added/modified actors
        es_query = {
            "query": {
                "match_all": {}
            },
            "size": 10,
            "sort": {
                "last_updated_s": {
                    "order": "desc"
                }
            }
        }

        #pull the query out of the url
        query_string = request.args.get("q")

        #someone is searching for something
        if request.method == 'POST' and not query_string:
            if form.validate():

                #get the value
                value = form.query.data

                #redirect to this same page, but setting the query value in the url
                return redirect("/?q={}".format(quote_plus(value)), code=307)

            else:
                #if there was an error print the error dictionary to the console
                #   temporary help, these should also appear under the form field
                print(form.errors)

        elif query_string:
            #now that the query_string is provided as ?q=, perform the search
            print("VALID SEARCH OPERATION DETECTED")

            #do some searching...
            es_query = {
                "query": {
                    "query_string": {
                        "query" : query_string
                    }
                },
                "size": 10
            }

            url += "?q=" + query_string
            query_string_url = "?q=" + query_string

            #set the form query value to what the user is searching for
            form.query.data = query_string

        '''
        Fetch the data from ES
        '''

        actors = {}
        actors['hits'] = {}
        actors['hits']['hits'] = []

        reports = dict(actors)

        ttps = dict(actors)
        
        try:
            actors = get_es().search(ES_PREFIX + 'threat_actors', 'actor', es_query)
        except TransportError as te:
            #if the index was not found, this is most likely becuase theres no data there
            if te.status_code == 404:
                log.warning("Index 'threat_actors' was not found")
            else:
                error = "There was an error fetching actors. Details: {}".format(te)
                flash(error,'danger')
                log.exception(logging_prefix + error)
        except Exception as e:
            error = "The was an error fetching Actors. Error: {}".format(e)
            log.exception(error)
            flash(error, "danger")

        try:
            reports = get_es().search(ES_PREFIX + 'threat_reports', 'report', es_query)
        except TransportError as te:
            #if the index was not found, this is most likely becuase theres no data there
            if te.status_code == 404:
                log.warning("Index 'threat_reports' was not found")
            else:
                error = "There was an error fetching reports. Details: {}".format(te)
                flash(error,'danger')
                log.exception(logging_prefix + error)
        except Exception as e:
            error = "The was an error fetching Reports. Error: {}".format(e)
            log.exception(error)
            flash(error, "danger")

        try:
            ttps = get_es().search(ES_PREFIX + 'threat_ttps', 'ttp', es_query)
        except TransportError as te:
            #if the index was not found, this is most likely becuase theres no data there
            if te.status_code == 404:
                log.warning("Index 'threat_ttps' was not found")
            else:
                error = "There was an error ttps. Details: {}".format(te)
                flash(error,'danger')
                log.exception(logging_prefix + error)
        except Exception as e:
            error = "The was an error fetching TTPs. Error: {}".format(e)
            log.exception(error)
            flash(error, "danger")
        
        '''
        Modify the data as needed
        '''

        for actor in actors['hits']['hits']:
            s = SALTS['actor'] + actor['_id']
            hash_object = hashlib.sha256(s.encode('utf-8'))
            hex_dig = hash_object.hexdigest()
            actor["_source"]['id_hash'] = hex_dig

        for report in reports['hits']['hits']:
            s = SALTS['report'] + report['_id']
            hash_object = hashlib.sha256(s.encode('utf-8'))
            hex_dig = hash_object.hexdigest()
            report["_source"]['id_hash'] = hex_dig

        for ttp in ttps['hits']['hits']:
            s = SALTS['ttp'] + ttp['_id']
            hash_object = hashlib.sha256(s.encode('utf-8'))
            hex_dig = hash_object.hexdigest()
            ttp["_source"]['id_hash'] = hex_dig

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        log.exception(error)
        flash(error, "danger")

    #render the template, passing the variables we need
    #   templates live in the templates folder
    return render_template("index.html",
                        page_title="ActorTrackr",
                        form=form,
                        query_string_url=query_string_url,
                        actors=actors,
                        reports=reports,
                        ttps=ttps,
                        url = quote_plus(url)
            )

@index_blueprint.route("/export", methods = ['GET'])
@index_blueprint.route("/export/", methods = ['GET'])
@authentication.access(authentication.PUBLIC)
def export_all_the_data():
    logging_prefix = logger_prefix + "export_all_the_data() - "
    log.info(logging_prefix + "Exporting")

    try:
        dump = {}
        dump['actors'] = []
        dump['reports'] = []
        dump['ttps'] = []
        dump['choices'] = {}

        query = {
            "query" : {
                "match_all" : {}
            }
        }

        results = scan(get_es(),query=query,index=ES_PREFIX + "threat_actors",doc_type="actor")

        
        for i in results:
            dump['actors'].append(i)

        results = scan(get_es(),query=query,index=ES_PREFIX + "threat_reports",doc_type="report")

        for i in results:
            dump['reports'].append(i)

        results = scan(get_es(),query=query,index=ES_PREFIX + "threat_ttps",doc_type="ttp")

        for i in results:
            dump['ttps'].append(i)

        results = scan(get_es(),query=query,index=ES_PREFIX + "threat_actor_pc",doc_type="parent")

        dump['choices']['parents'] = []
        for i in results:
            dump['choices']['parents'].append(i)

        results = scan(get_es(),query=query,index=ES_PREFIX + "threat_actor_pc",doc_type="child")

        dump['choices']['children'] = []
        for i in results:
            dump['choices']['children'].append(i)

        results = scan(get_es(),query=query,index=ES_PREFIX + "threat_actor_simple",doc_type="data")

        dump['choices']['simple'] = []
        for i in results:
            dump['choices']['simple'].append(i)

        # We need to modify the response, so the first thing we 
        # need to do is create a response out of the Dictionary
        response = make_response(json.dumps(dump))

        # This is the key: Set the right header for the response
        # to be downloaded, instead of just printed on the browser
        response.headers["Content-Disposition"] = "attachment; filename=export.json"
        response.headers["Content-Type"] = "text/json; charset=utf-8"

        return response

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        log.exception(error)
        flash(error, "danger")
        return redirect("/")

@index_blueprint.route("/<t>", methods = ['GET','POST'])
@index_blueprint.route("/<t>/", methods = ['GET','POST'])
@index_blueprint.route("/<t>/<page>", methods = ['GET','POST'])
@index_blueprint.route("/<t>/<page>/", methods = ['GET','POST'])
def view_all(t,page=1):
    if t == 'favicon.ico':
        return jsonify({}),404

    page = int(page)

    logging_prefix = logger_prefix + "view_all() - "
    log.info(logging_prefix + "Loading view all page {} for {}".format(page, t))
    
    form = forms.searchForm(request.form)
    error = None
    page_size = 50
    offset = (page-1) * page_size
    url = "/{}/{}/".format(t,page)
    search_url = ""
    results_text = ""
    try:


        #this is the default query for actors in ES, i'd imagine this will be recently added/modified actors
        es_query = {
            "query": {
                "match_all": {}
            },
            "size": page_size,
            "from" : offset,
            "sort": {
                "last_updated_s": {
                    "order": "desc"
                }
            }
        }

        #pull the query out of the url
        query_string = request.args.get("q")

        #someone is searching for something
        if request.method == 'POST' and not query_string:
            if form.validate():
                print("VALID SEARCH OPERATION DETECTED, redirecting...")

                #get the value
                value = form.query.data


                log.info(value)

                #redirect to this same page, but setting the query value in the url
                return redirect("/{}/1/?q={}".format(t,quote_plus(value)), code=307)

            else:
                #if there was an error print the error dictionary to the console
                #   temporary help, these should also appear under the form field
                print(form.errors)

        elif query_string:
            #now that the query_string is provided as ?q=, perform the search
            print("VALID SEARCH OPERATION DETECTED")

            #do some searching...
            es_query = {
                "query": {
                    "query_string": {
                        "query" : query_string
                    }
                },
                "size": page_size,
                "from" : offset
            }

            search_url = "?q=" + query_string
            #set the form query value to what the user is searching for
            form.query.data = query_string

        '''
        Fetch the data from ES
        '''

        data = {}
        data['hits'] = {}
        data['hits']['hits'] = []

        if t == 'actor':
            index = ES_PREFIX + 'threat_actors'
            doc_type = 'actor'
            salt = SALTS['actor']
            link_prefix = 'actor'
            data_header = 'Actors'
            field_header = 'Actor Name'
        elif t == 'report':
            index = ES_PREFIX + 'threat_reports'
            doc_type = 'report'
            salt = SALTS['report']
            link_prefix = 'report'
            data_header = 'Reports'
            field_header = 'Report Title'
        elif t == 'ttp':
            index = ES_PREFIX + 'threat_ttps'
            doc_type = 'ttp'
            salt = SALTS['ttp']
            link_prefix = 'ttp'
            data_header = 'TTPs'
            field_header = 'TTP Name'
        else:
            raise Exception("Unknown type {}".format(t))

        try:
            data = get_es().search(index, doc_type, es_query)
            num_hits = len(data['hits']['hits'])

            #set up previous link
            if page == 1:
                prev_url = None
            else:
                prev_url = "/{}/{}/{}".format(t,(page-1),search_url)

            if ((page-1)*page_size) + num_hits <  data['hits']['total']:
                next_url = "/{}/{}/{}".format(t,(page+1),search_url)
            else:
                next_url = None
            
            url += search_url

            for d in data['hits']['hits']:
                s = salt + d['_id']
                hash_object = hashlib.sha256(s.encode('utf-8'))
                hex_dig = hash_object.hexdigest()
                d["_source"]['id_hash'] = hex_dig

            if num_hits == 0:
                results_text = ""
            else:
                f = ( (page-1) * page_size ) + 1
                l = f + (num_hits-1)
                results_text = "Showing {} to {} of {} total results".format(f,l,data['hits']['total'])

        except TransportError as te:

            #if the index was not found, this is most likely becuase theres no data there
            if te.status_code == 404:
                log.warning("Index '{}' was not found".format(index))
            else:
                error = "There was an error fetching {}. Details: {}".format(t, te)
                flash(error,'danger')
                log.exception(logging_prefix + error)

        except Exception as e:
            error = "The was an error fetching {}. Error: {}".format(t,e)
            log.exception(error)
            flash(error, "danger")
    

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        log.exception(error)
        flash(error, "danger")
        return redirect("/")

    return render_template("view_all.html",
                        page_title="View All",
                        form=form,
                        data_header=data_header,
                        results_text=results_text,
                        field_header=field_header,
                        data=data,
                        link_prefix=link_prefix,
                        prev_url=prev_url,
                        next_url=next_url,
                        url = quote_plus(url)
            )


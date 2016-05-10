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
from core.decorators import authentication
from core.forms import forms
from app import log, get_es, get_mysql
from utils.elasticsearch import *
from utils.functions import *

ttp_blueprint = Blueprint('ttp', __name__, url_prefix="/ttp")
logger_prefix = "ttp.py:"

def es_to_form(ttp_id):
    form = forms.ttpForm()

    #get the values from ES
    results = get_es().get(ES_PREFIX + "threat_ttps", doc_type="ttp", id=ttp_id)

    
    #store certain fields from ES, so this form can be used in an update
    form.doc_index.data = results['_index']
    form.doc_type.data = results['_type']

    ttp_data = results['_source']

    form.ttp_name.data = ttp_data['name']
    form.ttp_first_observed.data = datetime.strptime(ttp_data['created_s'],"%Y-%m-%dT%H:%M:%S")
    form.ttp_description.data = ttp_data['description']
    form.ttp_criticality.data = int(ttp_data['criticality'])

    idx = 0
    for entry in range(len(form.ttp_class.entries)): form.ttp_class.pop_entry()
    for i in multikeysort(ttp_data['classification'], ['family', 'id']):
        ttp_class_form = forms.TPXClassificationForm()
        ttp_class_form.a_family = i['family']
        ttp_class_form.a_id = i['id']

        form.ttp_class.append_entry(ttp_class_form)

        #set the options since this select is dynamic
        form.ttp_class[idx].a_id.choices = fetch_child_data('tpx_classification',i['family'])
        idx += 1

    if ttp_data['related_actor']:
        for entry in range(len(form.ttp_actors.entries)): form.ttp_actors.pop_entry()
        for i in multikeysort(ttp_data['related_actor'], ['name', 'id']):
            sub_form = forms.RelatedActorsForm()
            sub_form.data = i['id'] + ":::" + i['name']

            form.ttp_actors.append_entry(sub_form)

    if ttp_data['related_report']:
        for entry in range(len(form.ttp_reports.entries)): form.ttp_reports.pop_entry()
        for i in multikeysort(ttp_data['related_report'], ['name', 'id']):
            sub_form = forms.RelatedReportsForm()
            sub_form.data = i['id'] + ":::" + i['name']

            form.ttp_reports.append_entry(sub_form)
            
    if ttp_data['related_ttp']:
        for entry in range(len(form.ttp_ttps.entries)): form.ttp_ttps.pop_entry()
        for i in multikeysort(ttp_data['related_ttp'], ['name', 'id']):
            sub_form = forms.RelatedTTPsForm()
            sub_form.data = i['id'] + ":::" + i['name']

            form.ttp_ttps.append_entry(sub_form)

    return form

def es_to_tpx(ttp_id):
    '''
    Build the TPX file from the data stored in Elasticsearch
    '''
    element_observables = {}

    results = get_es().get(ES_PREFIX + "threat_ttps", doc_type="ttp", id=ttp_id)
    ttp_data = results['_source']

    tpx = {}
    tpx["schema_version_s"] = "2.2.0"
    tpx["provider_s"] = "LookingGlass"
    tpx["list_name_s"] = "Threat Actor"
    tpx["created_t"] = ttp_data['created_milli']
    tpx["created_s"] = ttp_data['created_s']
    tpx["last_updated_t"] = ttp_data['last_updated_milli']
    tpx["last_updated_s"] = ttp_data['last_updated_s']
    tpx["score_i"] = 95
    tpx["source_observable_s"] = "Cyveillance Threat Actor"
    tpx["source_description_s"] = "This feed provides threat actor or threat actor group profiles and characterizations created by the LookingGlass Cyber Threat Intelligence Group"

    tpx["observable_dictionary_c_array"] = []

    observable_dict = {}
    observable_dict["ttp_uuid_s"] = ttp_id
    observable_dict["observable_id_s"] = ttp_data['name']
    observable_dict["description_s"]  = ttp_data['description']
    observable_dict["criticality_i"] = ttp_data['criticality']

    observable_dict["classification_c_array"] = []

    class_dict = {}
    class_dict["score_i"] = 70
    class_dict["classification_id_s"] = "Intel"
    class_dict["classification_family_s"] = "TTP"
    observable_dict["classification_c_array"].append(class_dict)

    for i in ttp_data['classification']:
        class_dict = {}
        class_dict["score_i"] = i["score"]
        class_dict["classification_id_s"] = i["id"]
        class_dict["classification_family_s"] = i["family"]

        if class_dict not in observable_dict["classification_c_array"]:
            observable_dict["classification_c_array"].append(class_dict)

    observable_dict["related_ttps_c_array"]  = []
    for i in ttp_data['related_ttp']:
        if i['name']:
            observable_dict["related_ttps_c_array"].append({ "name_s" :  i['name'], "uuid_s" : i['id'] })


    observable_dict["related_actors_c_array"]  = []
    for i in ttp_data['related_actor']:
        if i['name']:
            observable_dict["related_actors_c_array"].append({ "name_s" :  i['name'], "uuid_s" : i['id'] })

    observable_dict["related_reports_c_array"]  = []
    for i in ttp_data['related_report']:
        if i['name']:
            observable_dict["related_reports_c_array"].append({ "name_s" :  i['name'], "uuid_s" : i['id'] })


    '''
    Related elements
    '''

    relate_element_name_map = {
            "FQDN" : "subject_fqdn_s",
            "IPv4" : "subject_ipv4_s",
            "TTP" : "subject_ttp_s",
            "CommAddr" : "subject_address_s"
        }



    tpx["observable_dictionary_c_array"].append(observable_dict)

    return tpx

def form_to_es(form, ttp_id):
    logging_prefix = logger_prefix + "form_to_es() - "
    log.info(logging_prefix + "Converting Form to ES for {}".format(ttp_id))

    doc = {}

    created_t = int(time.mktime(form.ttp_first_observed.data.timetuple())) * 1000
    created_s = form.ttp_first_observed.data.strftime("%Y-%m-%dT%H:%M:%S")
    now_t = int(time.time()) * 1000
    now_s = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    doc["created_milli"] = created_t
    doc["created_s"] = created_s
    doc["last_updated_milli"] = now_t
    doc["last_updated_s"] = now_s

    doc['name'] = escape(form.ttp_name.data)
    doc['description'] = escape(form.ttp_description.data)
    doc['criticality'] = int(escape(form.ttp_criticality.data))

    doc['classification'] = []
    for sub_form in form.ttp_class.entries:
        classification_dict = {}
        classification_dict['score'] = int(get_score(sub_form.data['a_family'], sub_form.data['a_id']))
        classification_dict['id'] = escape(sub_form.data['a_id'])
        classification_dict['family'] = escape(sub_form.data['a_family'])

        if classification_dict not in doc['classification']:
            doc['classification'].append(classification_dict)

    #Links to actors and reports
    doc['related_actor'] = []
    for sub_form in form.ttp_actors.entries:
        r_dict = {}
        data = escape(sub_form.data.data)

        if data == "_NONE_":
            continue

        data_array = data.split(":::")

        r_dict['id'] = escape(data_array[0])
        r_dict['name'] = escape(data_array[1])  
                                        #this is gonna be a nightmare to maintain, 
                                        # but it make sense to have this for searches
        
        if r_dict not in doc['related_actor']:                                
            doc['related_actor'].append(r_dict)

    doc['related_report'] = []
    for sub_form in form.ttp_reports.entries:
        r_dict = {}
        data = escape(sub_form.data.data)

        if data == "_NONE_":
            continue

        data_array = data.split(":::")

        r_dict['id'] = escape(data_array[0])
        r_dict['name'] = escape(data_array[1])  
                                        #this is gonna be a nightmare to maintain, 
                                        # but it make sense to have this for searches
        
        if r_dict not in doc['related_report']:                                
            doc['related_report'].append(r_dict)

    doc['related_ttp'] = []
    for sub_form in form.ttp_ttps.entries:
        r_dict = {}
        data = escape(sub_form.data.data)

        if data == "_NONE_":
            continue

        data_array = data.split(":::")

        r_dict['id'] = escape(data_array[0])
        r_dict['name'] = escape(data_array[1])  
                                        #this is gonna be a nightmare to maintain, 
                                        # but it make sense to have this for searches

        if r_dict not in doc['related_ttp']:                                
            doc['related_ttp'].append(r_dict)

    #print_tpx(doc)

    #index the doc
    log.info(logging_prefix + "Start Indexing of {}".format(ttp_id))
    response = get_es().index(ES_PREFIX + "threat_ttps", "ttp", doc, ttp_id)
    log.info(logging_prefix + "Done Indexing of {}".format(ttp_id))

    return response, doc

'''
TTP Pages
'''

@ttp_blueprint.route("/add", methods = ['GET','POST'])
@ttp_blueprint.route("/add/", methods = ['GET','POST']) 
@ttp_blueprint.route("/add/<template>/", methods = ['GET','POST'])  
@authentication.access(authentication.WRITE)
def add(template=None):
    logging_prefix = logger_prefix + "add({}) - ".format(template)
    log.info(logging_prefix + "Starting")

    try:
        form = forms.ttpForm(request.form)
        search_form = forms.searchForm()

        if request.method == 'POST':
            #trick the form validation into working with our dynamic drop downs
            for sub_form in form.ttp_class:
                sub_form.a_id.choices = fetch_child_data('tpx_classification',sub_form.a_family.data)

            #convert the field that lists the related_element_choices 
            #choices = []
            #rec = json.loads(form.related_element_choices.data)
            #for k,v in rec.items():
                #choices.append((v,k))

            if form.validate():
                log.info(logging_prefix + "Add Detected")

                #create a ttp id
                ttp_id = str(uuid.uuid4())

                #convert the form to ES format
                form_to_es(form, ttp_id)
               
                #rebuild the form from ES
                form = es_to_form(ttp_id)

                flash(Markup('<a href="/ttp/view/'+ttp_id+'" style="text-decoration:none; color:#3c763d;">New TTP Successfully Added. Click here to view this TTP</a>') , "success")
            else:
                #if there was an error print the error dictionary to the console
                #   temporary help, these should also appear under the form field
                print(form.errors)
        
        elif template:
            form = es_to_form(template)
        else:
            #populate certain fields with default data
            form.ttp_class[0].a_family.data = 'Actors'
            form.ttp_class[0].a_id.choices = fetch_child_data('tpx_classification','Actors')

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    return render_template("ttp.html",
                        page_title="Add New TTP",
                        role="ADD",
                        form=form,
                        search_form=search_form
            )

@ttp_blueprint.route("/view/<ttp_id>")
@ttp_blueprint.route("/view/<ttp_id>/") 
@authentication.access(authentication.PUBLIC)
def view(ttp_id):
    logging_prefix = logger_prefix + "view({}) - ".format(ttp_id)
    log.info(logging_prefix + "Starting")

    try:
        form = es_to_form(ttp_id)
        search_form = forms.searchForm()
    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)
        form = forms.ttpForm()
    
    #render the template, passing the variables we need
    #   templates live in the templates folder
    return render_template("ttp.html",
                        page_title="View TTP",
                        role="VIEW",
                        ttp_id=ttp_id,
                        form=form,
                        search_form=search_form
            )

@ttp_blueprint.route("/edit/<ttp_id>", methods = ['GET','POST'])
@ttp_blueprint.route("/edit/<ttp_id>/", methods = ['GET','POST']) 
@authentication.access(authentication.WRITE)
def edit(ttp_id):
    logging_prefix = logger_prefix + "edit({}) - ".format(ttp_id)
    log.info(logging_prefix + "Starting")

    error = None
    try:
        if request.method == 'POST':
            form = forms.ttpForm(request.form)
            search_form = forms.searchForm()

            #trick the form validation into working with our dynamic drop downs
            for sub_form in form.ttp_class:
                sub_form.a_id.choices = fetch_child_data('tpx_classification',sub_form.a_family.data)
            
            #convert the field that lists the related_element_choices 
            #choices = []
            #rec = json.loads(form.related_element_choices.data)
            #for k,v in rec.items():
                #choices.append((v,k))

            if form.validate():
                log.info(logging_prefix + "Edit Detected")

                #convert the form to ES format
                form_to_es(form, ttp_id)
               
                #rebuild the form from ES
                form = es_to_form(ttp_id)

                flash("TTP Update Successful!" , "success")
            else:
                #if there was an error print the error dictionary to the console
                #   temporary help, these should also appear under the form field
                print(form.errors)
        else:
            form = es_to_form(ttp_id)

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)
        form = forms.ttpForm()

    #render the template, passing the variables we need
    #   templates live in the templates folder
    return render_template("ttp.html",
                        page_title="Edit TTP",
                        role="EDIT",
                        ttp_id=ttp_id,
                        form=form,
                        search_form=search_form
            )

@ttp_blueprint.route("/export/<ttp_id>")
@ttp_blueprint.route("/export/<ttp_id>/") 
@authentication.access(authentication.PUBLIC)
def export(ttp_id):
    logging_prefix = logger_prefix + "export({}) - ".format(ttp_id)
    log.info(logging_prefix + "Starting")

    try:
        tpx = es_to_tpx(ttp_id)
    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        log.exception(logging_prefix + error)

        tpx = { "error" : error }
        return jsonify(tpx), 500

    return jsonify(tpx), 200

@ttp_blueprint.route("/delete/<ttp_id>/<ttp_id_hash>")
@ttp_blueprint.route("/delete/<ttp_id>/<ttp_id_hash>/") 
@authentication.access(authentication.DELETE)
def delete(ttp_id, ttp_id_hash):
    s = SALTS['ttp'] + ttp_id
    hash_object = hashlib.sha256(s.encode('utf-8'))
    hex_dig = hash_object.hexdigest()

    if ttp_id_hash == hex_dig:
        try:
            get_es().delete(ES_PREFIX + "threat_ttps", "ttp", ttp_id)
            flash("TTP Deleted" , "success")
        except Exception as e:
            flash("There was an error deleting the TTP. Error: {}".format(e), "danger")
    else:
        flash("There was an error deleting the TTP" , "danger")

    redirect_url = request.args.get("_r")
    if not redirect_url:
        redirec_url = "/"

    #sleep a sec, make them think were busy, really its to give ES time to delete the doc
    time.sleep(2)

    return redirect(redirect_url, code=302)
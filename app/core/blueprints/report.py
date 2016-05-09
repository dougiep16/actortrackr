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

report_blueprint = Blueprint('report', __name__, url_prefix="/report")
logger_prefix = "report.py:"

def es_to_form(report_id):
    form = forms.reportForm()

    #get the values from ES
    results = get_es().get(ES_PREFIX + "threat_reports", doc_type="report", id=report_id)

    
    #store certain fields from ES, so this form can be used in an update
    form.doc_index.data = results['_index']
    form.doc_type.data = results['_type']

    report_data = results['_source']

    form.report_name.data = report_data['name']
    form.report_id.data = report_data['identifier']
    form.report_occurred_at.data = datetime.strptime(report_data['created_s'],"%Y-%m-%dT%H:%M:%S")
    form.report_description.data = report_data['description']
    form.report_criticality.data = report_data['criticality']

    idx = 0
    for entry in range(len(form.report_class.entries)): form.report_class.pop_entry()
    for i in multikeysort(report_data['classification'], ['family', 'id']):
        report_class_form = forms.TPXClassificationForm()
        report_class_form.a_family = i['family']
        report_class_form.a_id = i['id']

        form.report_class.append_entry(report_class_form)

        #set the options since this select is dynamic
        form.report_class[idx].a_id.choices = fetch_child_data('tpx_classification',i['family'])
        idx += 1

    form.report_tlp.data = int(report_data['tlp'])

    for entry in range(len(form.report_sections.entries)): form.report_sections.pop_entry()
    for i in multikeysort(report_data['section'], ['order']):
        report_section_form = forms.ReportSectionsForm()
        report_section_form.title = i['title']
        report_section_form.tlp = i['tlp']
        report_section_form.text = i['content']

        form.report_sections.append_entry(report_section_form)

    form.report_source_reliability.data = report_data["source_reliability"]
    form.report_info_reliability.data = report_data["info_reliability"]

    for entry in range(len(form.report_sources.entries)): form.report_sources.pop_entry()
    for i in sorted(report_data['source']):
        report_source_form = forms.ReportSourcesForm()
        report_source_form.source = i

        form.report_sources.append_entry(report_source_form)

    '''
    Related element
    '''
    
    for entry in range(len(form.report_actors.entries)): form.report_actors.pop_entry()
    if report_data['related_actor']:
        idx = 0
        for i in multikeysort(report_data['related_actor'], ['name', 'id']):
            sub_form = forms.RelatedActorsForm()
            sub_form.data = i['id'] + ":::" + i['name']
            has_related_elements = False

            idx2=0
            for entry in range(len(sub_form.related_elements.entries)): sub_form.related_elements.pop_entry()
            for j in multikeysort(report_data['related_element_choices'],['display_text']):
                sub_sub_form = forms.ElementObservablesFrom()

                sub_form.related_elements.append_entry(sub_sub_form)

                is_related = (j['value'] in i['elements'])
                sub_form.related_elements[idx2].element = is_related
                sub_form.related_elements[idx2].element_value = j['value']
                sub_form.related_elements[idx2].element_text = j['display_text']

                if is_related:
                    has_related_elements = True

                idx2 +=1

            form.report_actors.append_entry(sub_form)

            form.report_actors[idx].has_related_elements.data = has_related_elements
            idx+=1
    else:
        sub_form = forms.RelatedActorsForm()
        sub_form.data = "_NONE_"
        form.report_actors.append_entry(sub_form)
            
    for entry in range(len(form.report_reports.entries)): form.report_reports.pop_entry()
    if report_data['related_report']:
        idx = 0
        for i in multikeysort(report_data['related_report'], ['name', 'id']):
            sub_form = forms.RelatedReportsForm()
            sub_form.data = i['id'] + ":::" + i['name']
            has_related_elements = False

            idx2=0
            for entry in range(len(sub_form.related_elements.entries)): sub_form.related_elements.pop_entry()
            for j in multikeysort(report_data['related_element_choices'],['display_text']):
                sub_sub_form = forms.ElementObservablesFrom()

                sub_form.related_elements.append_entry(sub_sub_form)

                is_related = (j['value'] in i['elements'])
                sub_form.related_elements[idx2].element = is_related
                sub_form.related_elements[idx2].element_value = j['value']
                sub_form.related_elements[idx2].element_text = j['display_text']

                if is_related:
                    has_related_elements = True

                idx2 +=1

            form.report_reports.append_entry(sub_form)

            form.report_reports[idx].has_related_elements.data = has_related_elements
            idx+=1
    else:
        sub_form = forms.RelatedReportsForm()
        sub_form.data = "_NONE_"
        form.report_reports.append_entry(sub_form)

            
    for entry in range(len(form.report_ttps.entries)): form.report_ttps.pop_entry()
    if report_data['related_ttp']:
        idx = 0
        for i in multikeysort(report_data['related_ttp'], ['name', 'id']):
            sub_form = forms.RelatedTTPsForm()
            sub_form.data = i['id'] + ":::" + i['name']
            has_related_elements = False

            idx2=0
            for entry in range(len(sub_form.related_elements.entries)): sub_form.related_elements.pop_entry()
            for j in multikeysort(report_data['related_element_choices'],['display_text']):
                sub_sub_form = forms.ElementObservablesFrom()

                sub_form.related_elements.append_entry(sub_sub_form)

                is_related = (j['value'] in i['elements'])
                sub_form.related_elements[idx2].element = is_related
                sub_form.related_elements[idx2].element_value = j['value']
                sub_form.related_elements[idx2].element_text = j['display_text']

                if is_related:
                    has_related_elements = True

                idx2 +=1

            form.report_ttps.append_entry(sub_form)

            form.report_ttps[idx].has_related_elements.data = has_related_elements
            idx+=1
    else:
        sub_form = forms.RelatedTTPsForm()
        sub_form.data = "_NONE_"
        form.report_ttps.append_entry(sub_form)

    return form

def es_to_tpx(report_id):
    '''
    Build the TPX file from the data stored in Elasticsearch
    '''
    element_observables = {}

    results = get_es().get(ES_PREFIX + "threat_reports", doc_type="report", id=report_id)
    report_data = results['_source']

    tpx = {}
    tpx["schema_version_s"] = "2.2.0"
    tpx["provider_s"] = "LookingGlass"
    tpx["list_name_s"] = "Threat Intel Report"
    tpx["created_t"] = report_data['created_milli']
    tpx["created_s"] = report_data['created_s']
    tpx["last_updated_t"] = report_data['last_updated_milli']
    tpx["last_updated_s"] = report_data['last_updated_s']
    tpx["score_i"] = 95
    tpx["source_observable_s"] = "Cyveillance Threat Intel Report"
    tpx["source_description_s"] = "This feed provides threat intelligence reports created by the LookingGlass Cyber Threat Intelligence Group"

    tpx["observable_dictionary_c_array"] = []

    observable_dict = {}
    observable_dict["observable_id_s"] = report_data['name']
    observable_dict["ttp_uuid_s"] = report_id
    observable_dict["criticality_i"] = report_data['criticality']

    observable_dict["classification_c_array"] = []
    for i in report_data['classification']:
        class_dict = {}
        class_dict["score_i"] = i["score"]
        #class_dict["score_i"] = get_score(i["family"], i["id"])
        class_dict["classification_id_s"] = i["id"]
        class_dict["classification_family_s"] = i["family"]

        observable_dict["classification_c_array"].append(class_dict)

    observable_dict["description_s"]  = report_data['description']

    observable_dict["report_s_map"] = {}
    observable_dict["report_s_map"]["ctig_identifier_s"] = report_data["identifier"] 
    observable_dict["report_s_map"]["tlp_i"] = report_data["identifier"] 
    observable_dict["report_s_map"]["reliability_s"] = report_data["source_reliability"] + str(report_data["info_reliability"])
    observable_dict["report_s_map"]["title_s"] = report_data['name'] 

    observable_dict["report_s_map"]["sections_s_map_array"] = []
    for i in report_data['section']:

        section_dict = {}
        section_dict["section_title_s"] = i["title"]
        section_dict["section_tlp_i"] = i["tlp"]
        section_dict["section_order_i"] = i["order"]
        section_dict["section_content_s"] = i["content"]

        observable_dict["report_s_map"]["sections_s_map_array"].append(section_dict)

    tpx["observable_dictionary_c_array"].append(observable_dict)

    return tpx

def form_to_es(form, report_id):
    logging_prefix = logger_prefix + "form_to_es() - "
    log.info(logging_prefix + "Converting Form to ES for {}".format(report_id))

    doc = {}

    created_t = int(time.mktime(form.report_occurred_at.data.timetuple())) * 1000
    created_s = form.report_occurred_at.data.strftime("%Y-%m-%dT%H:%M:%S")
    now_t = int(time.time()) * 1000
    now_s = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    doc["created_milli"] = created_t
    doc["created_s"] = created_s
    doc["last_updated_milli"] = now_t
    doc["last_updated_s"] = now_s

    doc["name"] = escape(form.report_name.data)
    doc["identifier"] = escape(form.report_id.data)
    doc["description"] = escape(form.report_description.data)
    doc["criticality"] = escape(int(form.report_criticality.data))

    doc['classification'] = []
    for sub_form in form.report_class.entries:
        classification_dict = {}
        classification_dict['score'] = int(get_score(sub_form.data['a_family'], sub_form.data['a_id']))
        classification_dict['id'] = escape(sub_form.data['a_id'])
        classification_dict['family'] = escape(sub_form.data['a_family'])

        if classification_dict not in doc['classification']:
            doc['classification'].append(classification_dict)

    doc["tlp"] = int(escape(form.report_tlp.data))

    doc['section'] = []
    idx=1
    for sub_form in form.report_sections.entries:
        section_dict = {}
        section_dict['order'] = idx
        section_dict['title'] = escape(sub_form.title.data)
        section_dict['tlp'] = int(escape(sub_form.tlp.data))
        section_dict['content'] = escape(sub_form.text.data)
        idx+=1

        doc['section'].append(section_dict)

    doc["source_reliability"] = escape(form.report_source_reliability.data)
    doc["info_reliability"] = int(escape(form.report_info_reliability.data))

    doc['source'] = []
    for sub_form in form.report_sources.entries:
        source = sub_form.source.data
        if source not in doc['source']:
            doc['source'].append(source)

    '''
    Related elements
    '''

    my_id = report_id

    #Links to actors and reports
    doc['related_actor'] = []
    for sub_form in form.report_actors.entries:
        r_dict = {}
        data = escape(sub_form.data.data)

        if data == "_NONE_":

            continue

        data_array = data.split(":::")

        r_dict['id'] = escape(data_array[0])

        #if the related element's id = my id, dont add to es, this should only apply to current type
        if data_array[0] == my_id:
            flash("A related actor matched this actor, this entry has been discarded", "warning")
            continue

        r_dict['name'] = escape(data_array[1])  
                                        #this is gonna be a nightmare to maintain, 
                                        # but it make sense to have this for searches

        r_dict['elements'] = []
        for sub_sub_form in sub_form.related_elements.entries:
            if sub_sub_form.element.data:
                if sub_sub_form.element_value.data not in r_dict['elements']:
                    r_dict['elements'].append(sub_sub_form.element_value.data)

        if r_dict not in doc['related_actor']:                                
            doc['related_actor'].append(r_dict)

    doc['related_report'] = []
    for sub_form in form.report_reports.entries:
        r_dict = {}
        data = escape(sub_form.data.data)

        if data == "_NONE_":
            continue

        data_array = data.split(":::")

        r_dict['id'] = escape(data_array[0])

        #if the related element's id = my id, dont add to es, this should only apply to current type
        if data_array[0] == my_id:
            flash("A related report matched this report, this entry has been discarded", "warning")
            continue

        r_dict['name'] = escape(data_array[1])  
                                        #this is gonna be a nightmare to maintain, 
                                        # but it make sense to have this for searches
        
        r_dict['elements'] = []
        for sub_sub_form in sub_form.related_elements.entries:
            if sub_sub_form.element.data:
                if sub_sub_form.element_value.data not in r_dict['elements']:
                    r_dict['elements'].append(sub_sub_form.element_value.data)

        if r_dict not in doc['related_report']:                                
            doc['related_report'].append(r_dict)

    doc['related_ttp'] = []
    for sub_form in form.report_ttps.entries:
        r_dict = {}
        data = escape(sub_form.data.data)

        if data == "_NONE_":
            continue

        data_array = data.split(":::")

        r_dict['id'] = escape(data_array[0])

        #if the related element's id = my id, dont add to es, this should only apply to current type
        if data_array[0] == my_id:
            flash("A related TTP matched this TTP, this entry has been discarded", "warning")
            continue

        r_dict['name'] = escape(data_array[1])  
                                        #this is gonna be a nightmare to maintain, 
                                        # but it make sense to have this for searches

        r_dict['elements'] = []
        for sub_sub_form in sub_form.related_elements.entries:
            if sub_sub_form.element.data:
                if sub_sub_form.element_value.data not in r_dict['elements']:
                    r_dict['elements'].append(sub_sub_form.element_value.data)

        if r_dict not in doc['related_ttp']:                                
            doc['related_ttp'].append(r_dict)

    #store these to make life easier
    doc['related_element_choices'] = []
    rec = json.loads(form.related_element_choices.data)
    for k,v in rec.items():
        #dont include the n/a choice, as this will be first and handled manually
        if v != "_NONE_":
            #this will create a tuple ("display text", "value string")
            doc['related_element_choices'].append({"display_text" : k, "value" : v})

    #print_tpx(doc)

    #index the doc
    log.info(logging_prefix + "Start Indexing of {}".format(report_id))
    response = get_es().index(ES_PREFIX + "threat_reports", "report", doc, report_id)
    log.info(logging_prefix + "Done Indexing of {}".format(report_id))

    return response, doc


'''
Report Pages
'''

@report_blueprint.route("/add", methods = ['GET','POST'])
@report_blueprint.route("/add/", methods = ['GET','POST']) 
@report_blueprint.route("/add/<template>/", methods = ['GET','POST']) 
@authentication.access(authentication.WRITE)
def add(template=None):
    logging_prefix = logger_prefix + "add({}) - ".format(template)
    log.info(logging_prefix + "Starting")

    error = None
    try:
        form = forms.reportForm(request.form)
        search_form = forms.searchForm()

        if request.method == 'POST':
            #trick the form validation into working with our dynamic drop downs
            for sub_form in form.report_class:
                sub_form.a_id.choices = fetch_child_data('tpx_classification',sub_form.a_family.data)

            #convert the field that lists the related_element_choices 
            #choices = []
            #rec = json.loads(form.related_element_choices.data)
            #for k,v in rec.items():
                #choices.append((v,k))

            if form.validate():
                log.info(logging_prefix + "Add Detected")

                #create a ttp id
                report_id = str(uuid.uuid4())

                #convert the form to ES format
                form_to_es(form, report_id)
               
                #rebuild the form from ES
                form = es_to_form(report_id)

                flash(Markup('<a href="/report/view/'+report_id+'" style="text-decoration:none; color:#3c763d;">New Report Successfully Added. Click here to view this Report</a>') , "success")
            else:
                #if there was an error print the error dictionary to the console
                #   temporary help, these should also appear under the form field
                print(form.errors)
        
        elif template:
            form = es_to_form(template)
        else:
            #populate certain fields with default data
            form.report_class[0].a_family.data = 'Actors'
            form.report_class[0].a_id.choices = fetch_child_data('tpx_classification','Actors')

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)
        form = forms.reportForm()

    return render_template("report.html",
                        page_title="Add New Report",
                        role="ADD",
                        form=form,
                        search_form=search_form
            )

@report_blueprint.route("/view/<report_id>")
@report_blueprint.route("/view/<report_id>/")
@authentication.access(authentication.PUBLIC)
def view(report_id):
    logging_prefix = logger_prefix + "view({}) - ".format(report_id)
    log.info(logging_prefix + "Starting")

    error = None
    try:
        form = es_to_form(report_id)
        search_form = forms.searchForm()
    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)
        form = forms.reportForm()
    
    #render the template, passing the variables we need
    #   templates live in the templates folder
    return render_template("report.html",
                        page_title="View Report",
                        role="VIEW",
                        report_id=report_id,
                        form=form,
                        search_form=search_form
            )


@report_blueprint.route("/edit/<report_id>", methods = ['GET','POST'])
@report_blueprint.route("/edit/<report_id>/", methods = ['GET','POST'])
@authentication.access(authentication.WRITE)
def edit(report_id):
    logging_prefix = logger_prefix + "edit({}) - ".format(report_id)
    log.info(logging_prefix + "Starting")

    error = None
    try:
        if request.method == 'POST':
            form = forms.reportForm(request.form)
            search_form = forms.searchForm()

            #trick the form validation into working with our dynamic drop downs
            for sub_form in form.report_class:
                sub_form.a_id.choices = fetch_child_data('tpx_classification',sub_form.a_family.data)
            
            #convert the field that lists the related_element_choices 
            #choices = []
            #rec = json.loads(form.related_element_choices.data)
            #for k,v in rec.items():
                #choices.append((v,k))

            if form.validate():
                log.info(logging_prefix + "Edit Detected")

                #convert the form to ES format
                form_to_es(form, report_id)
               
                #rebuild the form from ES
                form = es_to_form(report_id)

                flash("Report Update Successful!" , "success")
            else:
                #if there was an error print the error dictionary to the console
                #   temporary help, these should also appear under the form field
                print(form.errors)
        else:
            form = es_to_form(report_id)

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)
        form = forms.reportForm()

    #render the template, passing the variables we need
    #   templates live in the templates folder
    return render_template("report.html",
                        page_title="Edit Report",
                        role="EDIT",
                        report_id=report_id,
                        form=form,
                        search_form=search_form
            )

@report_blueprint.route("/export/<report_id>")
@report_blueprint.route("/export/<report_id>/")
@authentication.access(authentication.PUBLIC)
def export(report_id):
    logging_prefix = logger_prefix + "export({}) - ".format(report_id)
    log.info(logging_prefix + "Starting")

    try:
        tpx = es_to_tpx(report_id)
    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        log.exception(logging_prefix + error)

        tpx = { "error" : error }
        return jsonify(tpx), 500

    return jsonify(tpx), 200

@report_blueprint.route("/delete/<report_id>/<report_id_hash>")
@report_blueprint.route("/delete/<report_id>/<report_id_hash>/")
@authentication.access(authentication.DELETE)
def delete(report_id, report_id_hash):
    s = SALTS['report'] + report_id
    hash_object = hashlib.sha256(s.encode('utf-8'))
    hex_dig = hash_object.hexdigest()

    if report_id_hash == hex_dig:
        try:
            get_es().delete(ES_PREFIX + "threat_reports", "report", report_id)
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
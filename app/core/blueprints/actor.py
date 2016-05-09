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

#blue print def
actor_blueprint = Blueprint('actor', __name__, url_prefix="/actor")
logger_prefix = "actor.py:"

def es_to_form(actor_id):
    form = forms.actorForm()

    #get the values from ES
    results = get_es().get(ES_PREFIX + "threat_actors", doc_type="actor", id=actor_id)

    #store certain fields from ES, so this form can be used in an update
    form.doc_index.data = results['_index']
    form.doc_type.data = results['_type']

    actor_data = results['_source']

    form.actor_name.data = actor_data['name']
    form.actor_occurred_at.data = datetime.strptime(actor_data['created_s'],"%Y-%m-%dT%H:%M:%S")
    form.actor_description.data  = actor_data['description']
    form.actor_criticality.data  = actor_data['criticality']

    #blank this field, and then add data
    idx = 0
    for entry in range(len(form.actor_class.entries)): form.actor_class.pop_entry()
    for i in multikeysort(actor_data['classification'], ['family', 'id']):
        actor_class_form = forms.TPXClassificationForm()
        actor_class_form.a_family = i['family']
        actor_class_form.a_id = i['id']

        form.actor_class.append_entry(actor_class_form)

        #set the options since this select is dynamic
        form.actor_class[idx].a_id.choices = fetch_child_data('tpx_classification',i['family'])
        idx += 1

    form.actor_tlp.data = str(actor_data['tlp'])

    for entry in range(len(form.actor_type.entries)): form.actor_type.pop_entry()
    for i in sorted(actor_data['type']):
        actor_type_form = forms.TypeForm()
        actor_type_form.a_type = i
        form.actor_type.append_entry(actor_type_form)


    for entry in range(len(form.actor_motivations.entries)): form.actor_motivations.pop_entry()
    for i in sorted(actor_data['motivation']):
        actor_motivation_form = forms.MotivationForm()
        actor_motivation_form.motivation = i
        actor_motivation_form.motivation_other = ""
        form.actor_motivations.append_entry(actor_motivation_form)

    for entry in range(len(form.actor_aliases.entries)): form.actor_aliases.pop_entry()
    for i in sorted(actor_data['alias']):
        actor_alias_form = forms.AliasForm()
        actor_alias_form.alias = i
        form.actor_aliases.append_entry(actor_alias_form)

    for entry in range(len(form.actor_comms.entries)): form.actor_comms.pop_entry()
    for i in multikeysort(actor_data['communication_address'], ['type', 'value']):
        actor_comms_form = forms.CommunicationsForm()
        actor_comms_form.a_type = i['type']
        actor_comms_form.a_type_other = ""
        actor_comms_form.address = i['value']
        form.actor_comms.append_entry(actor_comms_form)

    for entry in range(len(form.actor_financials.entries)): form.actor_financials.pop_entry()
    for i in multikeysort(actor_data['financial_account'], ['type', 'value']):
        actor_fin_form = forms.FinancialsForm()
        actor_fin_form.f_type = i['type']
        actor_fin_form.f_type_other = ""
        actor_fin_form.account = i['value']
        form.actor_financials.append_entry(actor_fin_form)

    for entry in range(len(form.actor_locations.entries)): form.actor_locations.pop_entry()
    for i in sorted(actor_data['frequented_location']):
        actor_locations_form = forms.LocationsForm()
        actor_locations_form.location = i
        form.actor_locations.append_entry(actor_locations_form)

    for entry in range(len(form.actor_affliations.entries)): form.actor_affliations.pop_entry()
    for i in sorted(actor_data['country_affiliation']):
        actor_affil_form = forms.AffiliationsForm()
        actor_affil_form.affiliation = i
        actor_affil_form.affiliation_other = ""
        form.actor_affliations.append_entry(actor_affil_form)

    for entry in range(len(form.actor_known_targets.entries)): form.actor_known_targets.pop_entry()
    for i in sorted(actor_data['known_target']):
        actor_known_target_form = forms.KnownTargetsForm()
        actor_known_target_form.target = i
        actor_known_target_form.target_other = ""
        form.actor_known_targets.append_entry(actor_known_target_form)

    for entry in range(len(form.actor_origin.entries)): form.actor_origin.pop_entry()
    #theres only one of these, at least there should be
    actor_affil_form = forms.AffiliationsForm()
    actor_affil_form.affiliation = actor_data['origin']
    actor_affil_form.affiliation_other = ""
    form.actor_origin.append_entry(actor_affil_form)

    for entry in range(len(form.actor_infra_ipv4.entries)): form.actor_infra_ipv4.pop_entry()
    for i in sorted(actor_data['infrastructure']['ipv4']):
        actor_infra_ipv4_form = forms.InfrastructureIPv4Form()
        actor_infra_ipv4_form.ipv4 = i
        form.actor_infra_ipv4.append_entry(actor_infra_ipv4_form)

    for entry in range(len(form.actor_infra_fqdn.entries)): form.actor_infra_fqdn.pop_entry()
    for i in sorted(actor_data['infrastructure']['fqdn']):
        actor_infra_fqdn_form = forms.InfrastructureIPv4Form()
        actor_infra_fqdn_form.fqdn = i
        form.actor_infra_fqdn.append_entry(actor_infra_fqdn_form)

    form.actor_infra_action.data = actor_data['infrastructure']['action']
    form.actor_infra_operation.data = actor_data['infrastructure']['operation']
    form.actor_infra_status.data = actor_data['infrastructure']['status']


    for entry in range(len(form.actor_infra_types.entries)): form.actor_infra_types.pop_entry()
    for i in sorted(actor_data['infrastructure']['type']):
        actor_infra_type_form = forms.InfrastructureTypesForm()
        actor_infra_type_form.infra_type = i
        form.actor_infra_types.append_entry(actor_infra_type_form)

    for entry in range(len(form.actor_detections.entries)): form.actor_detections.pop_entry()
    for i in multikeysort(actor_data['detection_rule'], ["type", "id"]):
        actor_detection_form = forms.DetectionsForm()
        actor_detection_form.d_type = i['type']
        actor_detection_form.rule_id = i['id']
        actor_detection_form.rule = i['value']
        form.actor_detections.append_entry(actor_detection_form)

    '''
    Related element
    '''
    
    for entry in range(len(form.actor_actors.entries)): form.actor_actors.pop_entry()
    if actor_data['related_actor']:
        idx = 0
        for i in multikeysort(actor_data['related_actor'], ['name', 'id']):
            sub_form = forms.RelatedActorsForm()
            sub_form.data = i['id'] + ":::" + i['name']
            has_related_elements = False

            idx2=0
            for entry in range(len(sub_form.related_elements.entries)): sub_form.related_elements.pop_entry()
            for j in multikeysort(actor_data['related_element_choices'],['display_text']):
                sub_sub_form = forms.ElementObservablesFrom()

                sub_form.related_elements.append_entry(sub_sub_form)

                is_related = (j['value'] in i['elements'])
                sub_form.related_elements[idx2].element = is_related
                sub_form.related_elements[idx2].element_value = j['value']
                sub_form.related_elements[idx2].element_text = j['display_text']

                if is_related:
                    has_related_elements = True

                idx2 +=1

            form.actor_actors.append_entry(sub_form)

            form.actor_actors[idx].has_related_elements.data = has_related_elements
            idx+=1
    else:
        sub_form = forms.RelatedActorsForm()
        sub_form.data = "_NONE_"
        form.actor_actors.append_entry(sub_form)
            
    for entry in range(len(form.actor_reports.entries)): form.actor_reports.pop_entry()
    if actor_data['related_report']:
        idx = 0
        for i in multikeysort(actor_data['related_report'], ['name', 'id']):
            sub_form = forms.RelatedReportsForm()
            sub_form.data = i['id'] + ":::" + i['name']
            has_related_elements = False

            idx2=0
            for entry in range(len(sub_form.related_elements.entries)): sub_form.related_elements.pop_entry()
            for j in multikeysort(actor_data['related_element_choices'],['display_text']):
                sub_sub_form = forms.ElementObservablesFrom()

                sub_form.related_elements.append_entry(sub_sub_form)

                is_related = (j['value'] in i['elements'])
                sub_form.related_elements[idx2].element = is_related
                sub_form.related_elements[idx2].element_value = j['value']
                sub_form.related_elements[idx2].element_text = j['display_text']

                if is_related:
                    has_related_elements = True

                idx2 +=1

            form.actor_reports.append_entry(sub_form)

            form.actor_reports[idx].has_related_elements.data = has_related_elements
            idx+=1
    else:
        sub_form = forms.RelatedReportsForm()
        sub_form.data = "_NONE_"
        form.actor_reports.append_entry(sub_form)

            
    for entry in range(len(form.actor_ttps.entries)): form.actor_ttps.pop_entry()
    if actor_data['related_ttp']:
        idx = 0
        for i in multikeysort(actor_data['related_ttp'], ['name', 'id']):
            sub_form = forms.RelatedTTPsForm()
            sub_form.data = i['id'] + ":::" + i['name']
            has_related_elements = False

            idx2=0
            for entry in range(len(sub_form.related_elements.entries)): sub_form.related_elements.pop_entry()
            for j in multikeysort(actor_data['related_element_choices'],['display_text']):
                sub_sub_form = forms.ElementObservablesFrom()

                sub_form.related_elements.append_entry(sub_sub_form)

                is_related = (j['value'] in i['elements'])
                sub_form.related_elements[idx2].element = is_related
                sub_form.related_elements[idx2].element_value = j['value']
                sub_form.related_elements[idx2].element_text = j['display_text']

                if is_related:
                    has_related_elements = True

                idx2 +=1

            form.actor_ttps.append_entry(sub_form)

            form.actor_ttps[idx].has_related_elements.data = has_related_elements
            idx+=1

    else:
        sub_form = forms.RelatedTTPsForm()
        sub_form.data = "_NONE_"
        form.actor_ttps.append_entry(sub_form)

    return form

def es_to_tpx(actor_id):
    '''
    Build the TPX file from the data stored in Elasticsearch
    '''
    element_observables = {}

    results = get_es().get(ES_PREFIX + "threat_actors", doc_type="actor", id=actor_id)
    actor_data = results['_source']

    tpx = {}
    tpx["schema_version_s"] = "2.2.0"
    tpx["provider_s"] = "LookingGlass"
    tpx["list_name_s"] = "Threat Actor"
    tpx["created_t"] = actor_data['created_milli']
    tpx["created_s"] = actor_data['created_s']
    tpx["last_updated_t"] = actor_data['last_updated_milli']
    tpx["last_updated_s"] = actor_data['last_updated_s']
    tpx["score_i"] = 95
    tpx["source_observable_s"] = "Cyveillance Threat Actor"
    tpx["source_description_s"] = "This feed provides threat actor or threat actor group profiles and characterizations created by the LookingGlass Cyber Threat Intelligence Group"

    tpx["observable_dictionary_c_array"] = []

    observable_dict = {}
    observable_dict["observable_id_s"] = actor_data['name']
    observable_dict["actor_uuid_s"] = actor_id
    observable_dict["criticality_i"] = actor_data['criticality']

    observable_dict["classification_c_array"] = []
    for i in actor_data['classification']:
        class_dict = {}
        class_dict["score_i"] = i["score"]
        #class_dict["score_i"] = get_score(i["family"], i["id"])
        class_dict["classification_id_s"] = i["id"]
        class_dict["classification_family_s"] = i["family"]

        observable_dict["classification_c_array"].append(class_dict)

    observable_dict["description_s"]  = actor_data['description']

    observable_dict["attribute_c_map"]  = {}

    observable_dict["attribute_c_map"]["last_seen_t"]  = actor_data['last_updated_milli']
    observable_dict["attribute_c_map"]["last_seen_s"]  = actor_data['last_updated_s']

    observable_dict["attribute_c_map"]["tlp_i"]  = actor_data['tlp']

    observable_dict["attribute_c_map"]["motivation_s_array"]  = []
    for i in actor_data["motivation"]:
        observable_dict["attribute_c_map"]["motivation_s_array"].append(i)

    observable_dict["attribute_c_map"]["aliases_s_array"]  = []
    for i in actor_data["alias"]:
        if i: #make sure its not blank
            observable_dict["attribute_c_map"]["aliases_s_array"].append(i)

    observable_dict["attribute_c_map"]["communications_c_map"]  = {}
    if "communication_address" in actor_data:
        for i in actor_data["communication_address"]:
            #build the key, this is a bit tricky if the user enters special characters,
            #or has multiple spaces (possible trailing space, should address this when the
            # data is submitted) the key could get messed up.
            # Example: Jabber -> jabber_s_array
            key = i['type'].lower().replace(" ","_") +"_s_array"

            if key not in observable_dict["attribute_c_map"]["communications_c_map"]:
                observable_dict["attribute_c_map"]["communications_c_map"][key] = []

            if i['value']:
                observable_dict["attribute_c_map"]["communications_c_map"][key].append(i['value'])

                #this field is used in the element observable c array, lets keep track of it
                field_name = "subject_address_s"
                field_type = i['type']
                field_data = i['value']
                field_observable = actor_data['name']
                
                if field_name not in element_observables:
                    element_observables[field_name] = {}

                if field_type not in element_observables[field_name]:
                    element_observables[field_name][field_type] = {}

                if field_data not in element_observables[field_name][field_type]:
                    element_observables[field_name][field_type][field_data] = []

                if field_observable not in element_observables[field_name][field_type][field_data]:
                    element_observables[field_name][field_type][field_data].append(field_observable)

    observable_dict["attribute_c_map"]["financial_accounts_c_map"]  = {}
    if "financial_account" in actor_data:
        for i in actor_data["financial_account"]:
            #build the key, this is a bit tricky if the user enters special characters,
            #or has multiple spaces (possible trailing space, should address this when the
            # data is submitted) the key could get messed up.
            # Example: Jabber -> jabber_s_array
            key = i['type'].lower().replace(" ","_") +"_s_array"

            if key not in observable_dict["attribute_c_map"]["financial_accounts_c_map"]:
                observable_dict["attribute_c_map"]["financial_accounts_c_map"][key] = []

            if i['value']:
                observable_dict["attribute_c_map"]["financial_accounts_c_map"][key].append(i['value'])

    observable_dict["attribute_c_map"]["frequent_locations_s_array"]  = []
    for i in actor_data["frequented_location"]:
        if i:
            observable_dict["attribute_c_map"]["frequent_locations_s_array"].append(i)

    observable_dict["attribute_c_map"]["affiliations_s_array"]  = []
    for i in actor_data["country_affiliation"]:
        observable_dict["attribute_c_map"]["affiliations_s_array"].append(i)

    observable_dict["attribute_c_map"]["known_targets_s_array"]  = []
    for i in actor_data["known_target"]:
        observable_dict["attribute_c_map"]["known_targets_s_array"].append(i)

    observable_dict["attribute_c_map"]["suspected_point_of_origin_s"]  = actor_data['origin']
    
    observable_dict["attribute_c_map"]["infrastructure_ipv4_s_array"]  = []
    for i in actor_data["infrastructure"]["ipv4"]:
        if i:
            observable_dict["attribute_c_map"]["infrastructure_ipv4_s_array"].append(i)

            #this field is used in the element observable c array, lets keep track of it
            field_name = "subject_ipv4_s"
            field_type = "_DEFAULT_"
            field_data = i
            field_observable = actor_data['name']
            
            if field_name not in element_observables:
                element_observables[field_name] = {}

            if field_type not in element_observables[field_name]:
                element_observables[field_name][field_type] = {}

            if field_data not in element_observables[field_name][field_type]:
                element_observables[field_name][field_type][field_data] = []

            if field_observable not in element_observables[field_name][field_type][field_data]:
                element_observables[field_name][field_type][field_data].append(field_observable)
    
    observable_dict["attribute_c_map"]["infrastructure_fqdn_s_array"]  = []
    for i in actor_data["infrastructure"]["fqdn"]:
        if i:
            observable_dict["attribute_c_map"]["infrastructure_fqdn_s_array"].append(i)

            #this field is used in the element observable c array, lets keep track of it
            field_name = "subject_fqdn_s"
            field_type = "_DEFAULT_"
            field_data = i
            field_observable = actor_data['name']
            
            if field_name not in element_observables:
                element_observables[field_name] = {}

            if field_type not in element_observables[field_name]:
                element_observables[field_name][field_type] = {}

            if field_data not in element_observables[field_name][field_type]:
                element_observables[field_name][field_type][field_data] = []

            if field_observable not in element_observables[field_name][field_type][field_data]:
                element_observables[field_name][field_type][field_data].append(field_observable)

    observable_dict["attribute_c_map"]["infrastructure_action_s"]  = actor_data["infrastructure"]["action"]
    observable_dict["attribute_c_map"]["infrastructure_operation_s"]  = actor_data["infrastructure"]["operation"]
    observable_dict["attribute_c_map"]["infrastructure_status_s"]  = actor_data["infrastructure"]["status"]

    observable_dict["attribute_c_map"]["infrastructure_type_s_array"]  = []
    for i in actor_data["infrastructure"]["type"]:
        observable_dict["attribute_c_map"]["infrastructure_type_s_array"].append(i)

    observable_dict["attribute_c_map"]["detection_c_map"]  = {}
    for i in actor_data["detection_rule"]:
        #build the key, this is a bit tricky if the user enters special characters,
        #or has multiple spaces (possible trailing space, should address this when the
        # data is submitted) the key could get messed up.
        # Example: Snort -> snort_rule_s_map
        key = i['type'].lower().replace(" ","_") +"_s_map"

        if not i['value']:
            continue

        if key not in observable_dict["attribute_c_map"]["detection_c_map"]:
            observable_dict["attribute_c_map"]["detection_c_map"][key] = {}

        observable_dict["attribute_c_map"]["detection_c_map"][key][i['id']] = i['value']

    '''
    Related elements
    '''

    relate_element_name_map = {
            "FQDN" : "subject_fqdn_s",
            "IPv4" : "subject_ipv4_s",
            "TTP" : "subject_ttp_s",
            "CommAddr" : "subject_address_s"
        }

    observable_dict["attribute_c_map"]["related_ttps_c_array"]  = []
    for i in actor_data['related_ttp']:
        if i['name']:
            observable_dict["attribute_c_map"]["related_ttps_c_array"].append({ "name_s" :  i['name'], "uuid_s" : i['id'] })
            field_observable = i['name']

            for j in i['elements']:
                element_array = j.split(":::")

                if len(element_array) == 3:
                    field_type = element_array[0]
                    field_name = relate_element_name_map[element_array[1]]
                    field_data = element_array[2]
                elif len(element_array) == 2:
                    field_type = "_DEFAULT_"
                    field_name = relate_element_name_map[element_array[0]]
                    field_data = element_array[1]
                else:
                    raise Exception("Invalid element '{}'".format(j))

                if field_name not in element_observables:
                    element_observables[field_name] = {}

                if field_type not in element_observables[field_name]:
                    element_observables[field_name][field_type] = {}

                if field_data not in element_observables[field_name][field_type]:
                    element_observables[field_name][field_type][field_data] = []

                if field_observable not in element_observables[field_name][field_type][field_data]:
                    element_observables[field_name][field_type][field_data].append(field_observable)


    observable_dict["attribute_c_map"]["related_actors_c_array"]  = []
    for i in actor_data['related_actor']:
        if i['name']:
            observable_dict["attribute_c_map"]["related_actors_c_array"].append({ "name_s" :  i['name'], "uuid_s" : i['id'] })
            field_observable = i['name']

            for j in i['elements']:
                element_array = j.split(":::")

                if len(element_array) == 3:
                    field_type = element_array[0]
                    field_name = relate_element_name_map[element_array[1]]
                    field_data = element_array[2]
                elif len(element_array) == 2:
                    field_type = "_DEFAULT_"
                    field_name = relate_element_name_map[element_array[0]]
                    field_data = element_array[1]
                else:
                    raise Exception("Invalid element '{}'".format(j))

                if field_name not in element_observables:
                    element_observables[field_name] = {}

                if field_type not in element_observables[field_name]:
                    element_observables[field_name][field_type] = {}

                if field_data not in element_observables[field_name][field_type]:
                    element_observables[field_name][field_type][field_data] = []

                if field_observable not in element_observables[field_name][field_type][field_data]:
                    element_observables[field_name][field_type][field_data].append(field_observable)

    observable_dict["attribute_c_map"]["related_reports_c_array"]  = []
    for i in actor_data['related_report']:
        if i['name']:
            observable_dict["attribute_c_map"]["related_reports_c_array"].append({ "name_s" :  i['name'], "uuid_s" : i['id'] })
            field_observable = i['name']

            for j in i['elements']:
                element_array = j.split(":::")

                if len(element_array) == 3:
                    field_type = element_array[0]
                    field_name = relate_element_name_map[element_array[1]]
                    field_data = element_array[2]
                elif len(element_array) == 2:
                    field_type = "_DEFAULT_"
                    field_name = relate_element_name_map[element_array[0]]
                    field_data = element_array[1]
                else:
                    raise Exception("Invalid element '{}'".format(j))

                if field_name not in element_observables:
                    element_observables[field_name] = {}

                if field_type not in element_observables[field_name]:
                    element_observables[field_name][field_type] = {}

                if field_data not in element_observables[field_name][field_type]:
                    element_observables[field_name][field_type][field_data] = []

                if field_observable not in element_observables[field_name][field_type][field_data]:
                    element_observables[field_name][field_type][field_data].append(field_observable)


    tpx["observable_dictionary_c_array"].append(observable_dict)

    tpx["element_observable_c_array"] = []

    for field,val in element_observables.items():
        for sub_type, val1 in val.items():
            for data, val2 in val1.items():
                e_dict = {}

                e_dict[field] = data

                if sub_type != "_DEFAULT_":
                    e_dict['type_s'] = sub_type

                e_dict["threat_observable_c_map"] = {}
                for observable_id in val2:
                     e_dict["threat_observable_c_map"][observable_id] = {}

                     e_dict["threat_observable_c_map"][observable_id]["occurred_at_t"] = actor_data['created_milli']
                     e_dict["threat_observable_c_map"][observable_id]["occurred_at_s"] = actor_data['created_s']
                     e_dict["threat_observable_c_map"][observable_id]["last_seen_t"] = actor_data['last_updated_milli']
                     e_dict["threat_observable_c_map"][observable_id]["last_seen_s"] = actor_data['last_updated_s']

                tpx["element_observable_c_array"].append(e_dict)

    return tpx

def form_to_es(form, actor_id, update=False):

    doc = {}
    element_observables = {}

    doc["approval_state"] = 0   # 0 - newly added
                                # 1 - scores have been approved and this actor is ready for SV

    created_t = int(time.mktime(form.actor_occurred_at.data.timetuple())) * 1000
    created_s = form.actor_occurred_at.data.strftime("%Y-%m-%dT%H:%M:%S")
    now_t = int(time.time()) * 1000
    now_s = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    doc["created_milli"] = created_t
    doc["created_s"] = created_s
    doc["last_updated_milli"] = now_t
    doc["last_updated_s"] = now_s

    observable_dictionary = {}

    actor_name = form.actor_name.data

    doc['name'] = escape(actor_name)
    doc['criticality'] = int(escape(form.actor_criticality.data))

    doc['classification'] = []
    for sub_form in form.actor_class.entries:
        classification_dict = {}
        classification_dict['score'] = int(get_score(sub_form.data['a_family'], sub_form.data['a_id']))
        classification_dict['id'] = escape(sub_form.data['a_id'])
        classification_dict['family'] = escape(sub_form.data['a_family'])

        if classification_dict not in doc['classification']:
            doc['classification'].append(classification_dict)

    doc["description"] = escape(form.actor_description.data)
    
    doc["tlp"] = int(form.actor_tlp.data)

    '''
    Types 
    '''
    doc["type"] = [] # ??? should we change this to actor_type_s_array
    for sub_form in form.actor_type.entries:                                      # since the field is labeled Actor Types
        actor_type = sub_form.data['a_type']

        if actor_type not in doc["type"]:
            doc["type"].append(escape(actor_type))

    '''
    Motivations 
    '''
    doc['motivation'] = []
    for sub_form in form.actor_motivations.entries:
        motivation = sub_form.data['motivation']

        if motivation == '_NEW_':
            motivation = sub_form.data['motivation_other']
            add_to_store('motivation', motivation, True)

        if motivation not in doc['motivation']:
            doc['motivation'].append(escape(motivation))

    '''
    Aliases 
    '''
    doc['alias'] = []
    for sub_form in form.actor_aliases.entries:
        alias = sub_form.data['alias']

        if alias not in doc['alias']:
            doc['alias'].append(escape(alias))

    '''
    Communications 
    '''
    doc['communication_address'] = []
    for sub_form in form.actor_comms.entries:
        address = sub_form.data['address']
        comm_type = sub_form.data['a_type']

        if comm_type == "_NEW_":
            comm_type = sub_form.data['a_type_other']
            add_to_store('communication', comm_type, True)

        #since comm_type is used as a key in the tpx file, sanitize it first
        #comm_type = comm_type.lower().replace("  "," ").replace(" ","_") + "_s_array"

        data = {}
        data['type'] = escape(comm_type)
        data['value'] = escape(address)

        if data not in doc['communication_address']:
            doc['communication_address'].append(data)

    '''
    Financials 
    '''
    doc["financial_account"] = []
    for sub_form in form.actor_financials.entries:
        account = sub_form.data['account']
        fin_type = sub_form.data['f_type']

        if fin_type == "_NEW_":
            fin_type = sub_form.data['f_type_other']
            add_to_store('financial', fin_type, True)

        #since fin_type is used as a key in the tpx file, sanitize it first
        #fin_type = fin_type.lower().replace("  "," ").replace(" ","_") + "_s_array"

        data = {}
        data['type'] = escape(fin_type)
        data['value'] = escape(account)

        if data not in doc["financial_account"]:
            doc["financial_account"].append(data)

    '''
    Frequented Locations 
    '''
    doc["frequented_location"] = []
    for sub_form in form.actor_locations.entries:
        location = sub_form.data['location']

        if location not in doc["frequented_location"]:
            doc["frequented_location"].append(escape(location))

    '''
    Country Affliations 
    '''
    doc["country_affiliation"] = []
    for sub_form in form.actor_affliations.entries:
        affiliation = sub_form.data['affiliation']

        if affiliation == '_NEW_':
            affiliation = sub_form.data['affiliation_other']
            add_to_store('country', affiliation, True)

        if affiliation not in doc["country_affiliation"]:
            doc["country_affiliation"].append(escape(affiliation))

    '''
    Known Targets
    '''
    doc["known_target"] = []
    for sub_form in form.actor_known_targets.entries:
        target = sub_form.data['target']

        if target == '_NEW_':
            target = sub_form.data['target_other']
            add_to_store('known_target', target, True)

        if target not in doc["known_target"]:
            doc["known_target"].append(escape(target))

    '''
    Origin
    '''
    #this one is different, because i borrowed from the country_affliation sub form
    affiliation = form.actor_origin.data[0]['affiliation']

    if affiliation == '_NEW_':
        affiliation = form.actor_origin.data[0]['affiliation_other']
        add_to_store('country', affiliation, True)

    doc["origin"] = escape(affiliation)

    '''
    Infrastructure IPv4s
    '''
    doc['infrastructure'] = {}
    doc['infrastructure']['ipv4'] = []
    for sub_form in form.actor_infra_ipv4.entries:
        ip = sub_form.data['ipv4']

        if ip not in doc['infrastructure']['ipv4']:
            doc['infrastructure']['ipv4'].append(escape(ip))

    '''
    Infrastructure FQDNs
    '''
    doc['infrastructure']['fqdn'] = []
    for sub_form in form.actor_infra_fqdn.entries:
        fqdn = sub_form.data['fqdn']

        if fqdn not in doc['infrastructure']['fqdn']:
            doc['infrastructure']['fqdn'].append(escape(fqdn))

    '''
    Infrastructure Action, Operation, Status
    '''
    doc['infrastructure']['action'] = escape(form.actor_infra_action.data)
    doc['infrastructure']['operation'] = escape(form.actor_infra_operation.data)
    doc['infrastructure']['status'] = escape(form.actor_infra_status.data)
     
    '''
    Infrastructure Types
    '''
    doc['infrastructure']['type'] = []
    for sub_form in form.actor_infra_types.entries:
        _type = sub_form.data['infra_type']

        if location not in doc['infrastructure']['type']:
            doc['infrastructure']['type'].append(escape(_type))

    '''
    Detection Rules
    '''
    doc['detection_rule'] = []
    for sub_form in form.actor_detections.entries:
        rule = sub_form.data['rule']
        rule_id = sub_form.data['rule_id']
        rule_type = sub_form.data['d_type']

        #since comm_type is used as a key in the tpx file, sanitize it first
        #rule_type = rule_type.lower().replace("  "," ").replace(" ","_") + "_rule_s_array"
        
        data = {}
        data['type'] = escape(rule_type)
        data['value'] = escape(rule)
        data['id'] = escape(rule_id)

        if data not in doc['detection_rule']:
            doc['detection_rule'].append(data)


    '''
    Related elements
    '''

    my_id = actor_id

    #Links to actors and reports
    doc['related_actor'] = []
    for sub_form in form.actor_actors.entries:
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
    for sub_form in form.actor_reports.entries:
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
    for sub_form in form.actor_ttps.entries:
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

    #index the doc
    #print_tpx(doc['related_ttp'])
    #print_tpx(doc['related_element_choices'])
    #response = None

    response = get_es().index(ES_PREFIX + "threat_actors", "actor", doc, actor_id)

    return response, doc

'''
Actor Pages
'''

@actor_blueprint.route("/add", methods = ['GET','POST'])
@actor_blueprint.route("/add/", methods = ['GET','POST']) 
@actor_blueprint.route("/add/<template>/", methods = ['GET','POST'])  
@authentication.access(authentication.WRITE)
def add(template=None):
    logging_prefix = logger_prefix + "add({}) - ".format(template)
    log.info(logging_prefix + "Starting")

    error = None
    try:
        populate_simple_choices()
        form = forms.actorForm(request.form)
        search_form = forms.searchForm()

        if request.method == 'POST':
            #trick the form validation into working with our dynamic drop downs
            for sub_form in form.actor_class:
                sub_form.a_id.choices = fetch_child_data('tpx_classification',sub_form.a_family.data)

            #convert the field that lists the related_element_choices 
            #choices = []
            #rec = json.loads(form.related_element_choices.data)
            #for k,v in rec.items():
            #    choices.append((v,k))

            if form.validate():
                log.info(logging_prefix + "Add Detected")

                #create an actor id
                actor_id = str(uuid.uuid4())

                #convert the form to ES format
                form_to_es(form, actor_id)
               
                #rebuild the form from ES
                #flash('Not requerying ES, this should change', 'warning')
                form = es_to_form(actor_id)

                flash(Markup('<a href="/actor/view/'+actor_id+'" style="text-decoration:none; color:#3c763d;">New Actor Successfully Added. Click here to view this actor</a>') , "success")

                #return redirect("/add/{}/".format(actor_id), code=302)
            else:
                #if there was an error print the error dictionary to the console
                #   temporary help, these should also appear under the form field
                print(form.errors)
        
        elif template:
            form = es_to_form(template)
        else:
            #populate certain fields with default data
            form.actor_class[0].a_family.data = 'Actors'
            form.actor_class[0].a_id.choices = fetch_child_data('tpx_classification','Actors')

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    return render_template("actor.html",
                        page_title="Add New Actor",
                        role="ADD",
                        form=form,
                        search_form = search_form
            )

@actor_blueprint.route("/view/<actor_id>")
@actor_blueprint.route("/view/<actor_id>/") 
@authentication.access(authentication.PUBLIC)
def view(actor_id):
    logging_prefix = logger_prefix + "view({}) - ".format(actor_id)
    log.info(logging_prefix + "Starting")
    
    try:
        populate_simple_choices()
        form = es_to_form(actor_id)

        search_form = forms.searchForm()
    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)
        form = forms.actorForm()

    #render the template, passing the variables we need
    #   templates live in the templates folder
    return render_template("actor.html",
                        page_title="View Actor",
                        role="VIEW",
                        actor_id=actor_id,
                        form=form,
                        search_form = search_form
            )

@actor_blueprint.route("/edit/<actor_id>", methods = ['GET','POST'])
@actor_blueprint.route("/edit/<actor_id>/", methods = ['GET','POST']) 
@authentication.access(authentication.WRITE)
def edit(actor_id):
    logging_prefix = logger_prefix + "edit({}) - ".format(actor_id)
    log.info(logging_prefix + "Starting")
    
    try:
        populate_simple_choices()
        form = forms.actorForm(request.form)
        search_form = forms.searchForm()

        if request.method == 'POST':
            #trick the form validation into working with our dynamic drop downs
            for sub_form in form.actor_class:
                sub_form.a_id.choices = fetch_child_data('tpx_classification',sub_form.a_family.data)

            if form.validate():
                log.info(logging_prefix + "Edit Detected")

                #convert the form to ES format
                form_to_es(form, actor_id)
               
                #rebuild the form from ES
                form = es_to_form(actor_id)

                flash("Actor Update Successful!" , "success")
                #return redirect("/edit/{}/".format(actor_id), code=302)
            else:
                #if there was an error print the error dictionary to the console
                #   temporary help, these should also appear under the form field
                print(form.errors)
        else:
            form = es_to_form(actor_id)

    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    #render the template, passing the variables we need
    #   templates live in the templates folder
    return render_template("actor.html",
                        page_title="Edit Actor",
                        role="EDIT",
                        actor_id=actor_id,
                        form=form,
                        search_form = search_form
            )

@actor_blueprint.route("/export/<actor_id>")
@actor_blueprint.route("/export/<actor_id>/") 
@authentication.access(authentication.PUBLIC)
def export(actor_id):
    logging_prefix = logger_prefix + "export({}) - ".format(actor_id)
    log.info(logging_prefix + "Starting")

    try:
        populate_simple_choices()
        tpx = es_to_tpx(actor_id)
    except Exception as e:
        error = "There was an error completing your request. Details: {}".format(e)
        log.exception(logging_prefix + error)

        tpx = { "error" : error }
        return jsonify(tpx), 500

    return jsonify(tpx), 200

@actor_blueprint.route("/delete/<actor_id>/<actor_id_hash>")
@actor_blueprint.route("/delete/<actor_id>/<actor_id_hash>/") 
@authentication.access(authentication.DELETE)
def delete(actor_id, actor_id_hash):
    s = SALTS['actor'] + actor_id
    hash_object = hashlib.sha256(s.encode('utf-8'))
    hex_dig = hash_object.hexdigest()

    if actor_id_hash == hex_dig:
        try:
            print(get_es().delete(ES_PREFIX + "threat_actors", "actor", actor_id))
            flash("Actor Deleted" , "success")
        except Exception as e:
            flash("There was an error deleting the actor. Error: {}".format(e), "danger")
    else:
        flash("There was an error deleting the actor" , "danger")

    redirect_url = request.args.get("_r")
    if not redirect_url:
        redirec_url = "/"

    #sleep a sec, make them think were busy, really its to give ES time to delete the doc
    time.sleep(2)

    return redirect(redirect_url, code=302)

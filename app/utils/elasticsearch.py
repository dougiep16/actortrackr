from flask import flash, g
from app import log, get_es
from config.settings import *

from elasticsearch import TransportError
from elasticsearch.helpers import scan

logger_prefix = "elasticsearch.py:"

SIMPLE_CHOICES = {}

def escape(v):
    '''
    Function for escaping data before it goes into ES

    Parameters: 
        v - the value to be escaped
    Returns:
        v - the escaped value, or the original value if escaping is not possible (int)
    '''

    #TODO: escape this before returning it, maybe?

    #trim the string
    try:
        v = v.strip()
    except AttributeError as a:
        #if its an integer strip doesnt apply
        pass
    return v


def populate_simple_choices():
    '''
    Populates the SIMPLE_CHOICES dictionary with options
    '''

    global SIMPLE_CHOICES

    SIMPLE_CHOICES = {}
    try:
        body = {
            "query" : {
                "match_all" : {}
            },
            "size" : 1000
        }
        results = get_es().search(ES_PREFIX + 'threat_actor_simple', 'data', body)

        for r in results['hits']['hits']:
            c_type = r['_source']['type']
            c_value = r['_source']['value']

            if c_type not in SIMPLE_CHOICES:
                SIMPLE_CHOICES[c_type] = []

            SIMPLE_CHOICES[c_type].append(c_value)

        for k,v in SIMPLE_CHOICES.items():
            SIMPLE_CHOICES[k] = sorted(v)

        #print(SIMPLE_CHOICES)

    except Exception as e:
        error = "There was an error fetching choices. Details: {}".format(t, e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

def fetch_data(c_type, add_new=False, add_unknown=False):
    d = []

    if not SIMPLE_CHOICES:
        populate_simple_choices()

    for value in sorted(SIMPLE_CHOICES[c_type]):
        d.append((value,value))

    if add_new:
        d.append(("_NEW_","Other"))

    if add_unknown:
        d.insert(0, ("Unknown", "Unknown"))
    
    #return the data
    return d

def fetch_parent_data(_type, add_new=False, add_unknown=False):
    d = []

    #query
    body = {
        "query" : {
            "term" : {
                "type" : _type
            }
        },
        "sort": {
            "value": {
                "order": "asc"
            }
        },
        "size" : 1000
    }

    #get the data!
    results = get_es().search(ES_PREFIX + 'threat_actor_pc', 'parent', body)
    for r in results['hits']['hits']:
        d.append((r['_source']['value'],r['_source']['value']))

    if add_new:
        d.append(("_NEW_","Other"))

    if add_unknown:
        d.insert(0, ("Unknown", "Unknown"))
    
    #return the data
    return d

def fetch_child_data(_type, parent, add_new=False, add_unknown=False):
    d = []

    #query
    body = {
        "query" : {
            "term" : {
                "_parent" : _type + " " + parent
            }
        },
        "sort": {
            "value": {
                "order": "asc"
            }
        },
        "size" : 1000
    }

    #get the data!
    results = get_es().search(ES_PREFIX + 'threat_actor_pc', 'child', body)
    for r in results['hits']['hits']:
        d.append((r['_source']['value'],r['_source']['value']))

    if add_new:
        d.append(("_NEW_","Other"))

    if add_unknown:
        d.insert(0, ("Unknown", "Unknown"))
    
    #return the data
    return d

def fetch_related_choices(t):
    logging_prefix = logger_prefix + "fetch_related_choices({}) - ".format(t)

    choices = [('_NONE_', 'n/a')]

    if t == 'actor':
        index = ES_PREFIX + "threat_actors"
        doc_type = "actor"
    elif t == 'report':
        index = ES_PREFIX + "threat_reports"
        doc_type = "report"
    elif t == 'ttp':
        index = ES_PREFIX + "threat_ttps"
        doc_type = "ttp"
    else:
        raise Exception("Invalid type '{}'. Expected 'actor', 'ttp' or 'report'")

    es_query = {
            "query": {
                "match_all": {}
            },
            "size": 1000,
            "fields" : ["name"],
            "sort": {
                "name": {
                    "order": "asc"
                }
            }
        }

    try:
        results = get_es().search(index, doc_type, es_query)
        for r in results['hits']['hits']:
            choices.append((r['_id'] + ":::" + r['fields']['name'][0],r['fields']['name'][0]))

    except TransportError as te:

        #if the index was not found, this is most likely becuase theres no data there
        if te.status_code == 404:
            log.warning("Index '{}' was not found".format(index))
        else:
            error = "There was an error fetching related {}s. Details: {}".format(t, te)
            flash(error,'danger')
            log.exception(logging_prefix + error)

    except Exception as e:
        error = "There was an error fetching related {}s. Details: {}".format(t, e)
        flash(error,'danger')
        log.exception(logging_prefix + error)

    return choices

def fetch_related_elements(t):
    if t == 'Actor':
        index = "tp-threat_actors"
        doc_type = "actor"
    elif t == 'Report':
        index = "tp-threat_reports"
        doc_type = "report"
    elif t == 'TTP':
        index = "tp-threat_ttps"
        doc_type = "ttp"
    else:
        return []

    query = {
        "query" : {
            "match_all" : {}
        },
        "sort" : {
            "name" : {
                "order" : "asc"
            }
        },
        "fields" : ["name"]
    }

    results = scan(get_es(),query=query,index=index,doc_type=doc_type,preserve_order=True)

    choices = []
    for r in results:
        _id = r["_id"]
        name = r["fields"]["name"][0]
        choices.append((_id + ":::" + name, name))

    return choices

def add_to_store(t, v, add_to_local=False):
    body = {
        "value" : escape(v),
        "type" : escape(t)
    }
    doc_id = t + " " + v
    get_es().index(ES_PREFIX + "threat_actor_simple", "data", body, doc_id)

    if add_to_local:
        global SIMPLE_CHOICES
        SIMPLE_CHOICES[t].append(v)

    print("Added {} {} to ES".format(v,t))

def get_score(classification_family, classification_id):
    #query
    body = {
        "query" : {
            "query_string" : {
                "query" : '+_parent:"tpx_classification {}" +value:"{}"'.format(escape(classification_family),escape(classification_id))
            }
        },
        "sort": {
            "value": {
                "order": "asc"
            }
        },
        "size" : 1
    }

    #get the data!
    results = get_es().search(ES_PREFIX + 'threat_actor_pc', 'child', body)
    if results['hits']['total'] != 1:
        raise Exception("Unable to perform score look up for {} - {}".format(classification_family,classification_id))

    return results['hits']['hits'][0]['_source']['score']

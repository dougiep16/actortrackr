#!/usr/bin/env python3.4
# update_mappings.py
#
# adds new mappings to each index to track which users modified an item
# this is a multi step script
# step 1. export all of the data from each index to a temp file
# step 2. delete the index/template for each index, recreate the template
# step 3. upload the dumped data

#import ES
try:
    from elasticsearch import Elasticsearch
    from elasticsearch import exceptions
    from elasticsearch.helpers import scan
except Exception as e:
    print("Error: {}\nElasticsearch library is not installed, try 'pip install elasticsearch'".format(e))
    exit(1)

# set up the path so this can be run and use the settings.py file
import json
import os
import requests
import sys
import time

# set PATH so imports are correct
TOP_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

APP_PATH = TOP_DIR+"/app"

sys.path.insert(0, TOP_DIR)
sys.path.insert(0, APP_PATH)

# Import our settings
from config.settings import *

#import the new mappings
import mappings_file

PERFORM_DELETE = True
NOOP = False

def getIndicesMatchingPattern(name):
    if name == '*' or name=='_all':
        raise Exception("Invalid Argument")

    print(name)
    url = "{}/{}".format(ES_HOSTS[0],name)
    print(url)
    r = requests.get(url)

    response = json.loads(r.content.decode('utf-8'))

    indices = []
    for k in response:
        indices.append(k)

    return indices

def delete_index_pattern(es, index):
    if not PERFORM_DELETE:
        print("NOT PERFORM INDEX DELETE DUE TO SETTINGS")
        return

    #Delete the Index 
    try:
        print("deleting indexes...")
        indices = getIndicesMatchingPattern(index)

        print(indices)
        time.sleep(3)

        for i in indices:
            if NOOP:
                print("NOOP - Deleting Index {}".format(i))
            else:
                print("[DELETE INDEX] Deleting Index {}".format(i))
                print(es.indices.delete(index=i))
        print("done")
    except exceptions.NotFoundError as e:
        print("Index not found")

def delete_template(es, template):
    if not PERFORM_DELETE:
        print("NOT PERFORM TEMPLATE DELETE DUE TO SETTINGS")
        return
    #Delete the Template
    try:
        if NOOP:
            print("NOOP - Deleting Template {}".format(template))
        else:
            print("[DELETE TEMPLATE] Deleting Template {}".format(template))
            print(es.indices.delete_template(name=template))
    except exceptions.NotFoundError as e:
        print("Template not found")

def create_template(es,name,body):
    if NOOP:
        print("NOOP - Creating Template {}".format(name))
    else:
        print("[CREATE TEMPLATE] Creating Template {}".format(name))
        print(es.indices.put_template(name=name, body=body))


def dump_to_file(es, index, doc_type):
    data = []

    query = {
        "query" : {
            "match_all" : {}
        }
    }

    results = scan(es,query=query,index=index,doc_type=doc_type)

    for i in results:
        data.append(i)

    with open(index + "__" + doc_type + ".dat", 'w') as f:
        f.write(json.dumps(data))

def delete_recreate(es, index, mapping):
    delete_index_pattern(es, index + "*")
    delete_template(es,index)

    create_template(es,name=index, body=mapping)

def import_from_file(es, index, doc_type):
    with open(index + "__" + doc_type + ".dat", 'r') as f:
        json_string = ""
        for line in f:
            json_string += line

        data = json.loads(json_string)

        count = 0
        for i in data:
            source = i['_source']

            source['editor'] = []
            count += 1
            print(es.index(index=index,doc_type=doc_type, body=source, id=i['_id']))

        print("{}.{} = {}".format(index,doc_type,count))



es = Elasticsearch(ES_HOSTS)

try:
    STEP = sys.argv[1]
except:
    STEP = None

if not STEP:
    exit("Usage {} <step>\nstep values\n\t1 - Export\n\t2 - Delete\n\t3 - Import".format(sys.argv[0]))

if STEP == "1":
    dump_to_file(es, ES_PREFIX + "threat_actors","actor")
    dump_to_file(es, ES_PREFIX + "threat_reports","report")
    dump_to_file(es, ES_PREFIX + "threat_ttps","ttp")

elif STEP == "2":
    delete_recreate(es, ES_PREFIX + "threat_actors", mappings_file.get_actor_mapping(ES_PREFIX))
    delete_recreate(es, ES_PREFIX + "threat_reports",mappings_file.get_report_mapping(ES_PREFIX))
    delete_recreate(es, ES_PREFIX + "threat_ttps", mappings_file.get_ttp_mapping(ES_PREFIX))

elif STEP == "3":
    import_from_file(es, ES_PREFIX + "threat_actors","actor")
    import_from_file(es, ES_PREFIX + "threat_reports","report")
    import_from_file(es, ES_PREFIX + "threat_ttps","ttp")

else:
    print("Invalid step '{}'".format(STEP))



#!/usr/bin/env python3.4
# Creates ES indexes for the threat actor application

from elasticsearch import Elasticsearch
from elasticsearch import exceptions
from elasticsearch.helpers import bulk
import requests
import json
import time

ES_PREFIX = "tp-"
PERFORM_DELETE = True
NOOP = False

def getIndicesMatchingPattern(name):
    if name == '*' or name=='_all':
        raise Exception("Invalid Argument")

    print(name)
    url = "http://localhost:9200/{}".format(name)
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


es = Elasticsearch(['localhost',])

'''
Simple Data
'''

delete_index_pattern(es,ES_PREFIX +"threat_actor_simple*")
delete_template(es,ES_PREFIX +"threat_actor_simple")

mapping = {
    "template" : ES_PREFIX + "threat_actor_simple",
    "mappings": {
      "data": {
         "properties": {
            "value": {
                "type": "string",
                "index": "not_analyzed"
            },
            "type": {
                "type": "string",
                "index": "not_analyzed"
            }
         }
      }
   },
    "settings" : {
        "number_of_shards"   : 5,
        "number_of_replicas" : 1
    }
}
create_template(es,name=ES_PREFIX+'threat_actor_simple', body=mapping)

'''
Parent Child Data
'''

delete_index_pattern(es,ES_PREFIX +"threat_actor_pc*")
delete_template(es,ES_PREFIX +"threat_actor_pc")

mapping = {
    "template" : ES_PREFIX + "threat_actor_pc",
    "mappings": {
        "parent": {
            "properties": {
                "value": {
                    "type": "string",
                    "index": "not_analyzed"
                },
                "type": {
                    "type": "string",
                    "index": "not_analyzed"
                }
            }
        },
        "child": {
            "_parent": {
                "type": "parent"
            },
            "properties": {
                "value": {
                    "type": "string",
                    "index": "not_analyzed"
                },
                "score": {
                    "type": "integer"
                }
            }
      }
    },
    "settings" : {
        "number_of_shards"   : 5,
        "number_of_replicas" : 1
    }
}
create_template(es,name=ES_PREFIX+'threat_actor_pc', body=mapping)

'''
Threat Actor Data
'''

delete_index_pattern(es,ES_PREFIX +"threat_actors*")
delete_template(es,ES_PREFIX +"threat_actors")


mapping = {
    "template" : ES_PREFIX + "threat_actors",
    "mappings":{  
        "actor":{  
            "properties":{  
                "alias":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "approval_state":{  
                    "type":"long"
                },
                "classification":{  
                    "properties":{  
                        "family":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "score":{  
                            "type":"long"
                        }
                    }
                },
                "communication_address":{  
                    "properties":{  
                        "type":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "value":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "country_affiliation":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "created_milli":{  
                    "type":"long"
                },
                "created_s":{  
                    "type":"date",
                    "format":"strict_date_optional_time||epoch_millis"
                },
                "criticality":{  
                    "type":"long"
                },
                "description":{  
                    "type":"string"
                },
                "detection_rule":{  
                    "properties":{  
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "type":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "value":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "editor" : {
                    "properties":{  
                        "user_id":{  
                            "type":"long"
                        },
                        "ts":{  
                            "type":"date",
                            "format":"strict_date_optional_time||epoch_millis"
                        }
                    }
                },
                "financial_account":{  
                    "properties":{  
                        "type":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "value":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "frequented_location":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "infrastructure":{  
                    "properties":{  
                        "action":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "fqdn":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "ipv4":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "operation":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "status":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "type":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "known_target":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "last_updated_milli":{  
                    "type":"long"
                },
                "last_updated_s":{  
                    "type":"date",
                    "format":"strict_date_optional_time||epoch_millis"
                },
                "motivation":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "name":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "origin":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "related_actor":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "related_element_choices":{  
                    "properties":{  
                        "display_text":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "value":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        }
                    }
                },
                "related_report":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "related_ttp":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "tlp":{  
                    "type":"long"
                },
                "type":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                }
            }
        }
    },
    "settings" : {
        "number_of_shards"   : 5,
        "number_of_replicas" : 1
    }
}

create_template(es,name=ES_PREFIX+'threat_actors', body=mapping)


'''
Threat Reports
'''

delete_index_pattern(es,ES_PREFIX +"threat_reports*")
delete_template(es,ES_PREFIX +"threat_reports")

mapping = {
    "template" : ES_PREFIX + "threat_reports",
    "mappings":{  
        "report":{  
            "properties":{  
                "classification":{  
                    "properties":{  
                        "family":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "score":{  
                            "type":"long"
                        }
                    }
                },
                "created_milli":{  
                    "type":"long"
                },
                "created_s":{  
                    "type":"date",
                    "format":"strict_date_optional_time||epoch_millis"
                },
                "criticality":{  
                    "type":"long"
                },
                "description":{  
                    "type":"string"
                },
                "editor" : {
                    "properties":{  
                        "user_id":{  
                            "type":"long"
                        },
                        "ts":{  
                            "type":"date",
                            "format":"strict_date_optional_time||epoch_millis"
                        }
                    }
                },
                "identifier":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "info_reliability":{  
                    "type":"string"
                },
                "last_updated_milli":{  
                    "type":"long"
                },
                "last_updated_s":{  
                    "type":"date",
                    "format":"strict_date_optional_time||epoch_millis"
                },
                "name":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "related_actor":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "related_element_choices":{  
                    "properties":{  
                        "display_text":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "value":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        }
                    }
                },
                "related_report":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "related_ttp":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "section":{  
                    "properties":{  
                        "content":{  
                            "type":"string"
                        },
                        "order":{  
                            "type":"long"
                        },
                        "title":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "tlp":{  
                            "type":"long"
                        }
                    }
                },
                "source":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "source_reliability":{  
                    "type":"string"
                },
                "tlp":{  
                    "type" : "long"
                }
            }
        }
    },
    "settings" : {
        "number_of_shards"   : 5,
        "number_of_replicas" : 1
    }
}

create_template(es,name=ES_PREFIX+'threat_reports', body=mapping)

'''
Threat TTPs
'''

delete_index_pattern(es,ES_PREFIX +"threat_ttps*")
delete_template(es,ES_PREFIX +"threat_ttps")

mapping = {
    "template" : ES_PREFIX + "threat_ttps",
    "mappings":{  
        "ttp":{  
            "properties":{  
                "classification":{  
                    "properties":{  
                        "family":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "score":{  
                            "type":"long"
                        }
                    }
                },
                "created_milli":{  
                    "type":"long"
                },
                "created_s":{  
                    "type":"date",
                    "format":"strict_date_optional_time||epoch_millis"
                },
                "criticality":{  
                    "type":"long"
                },
                "description":{  
                    "type":"string"
                },
                "editor" : {
                    "properties":{  
                        "user_id":{  
                            "type":"long"
                        },
                        "ts":{  
                            "type":"date",
                            "format":"strict_date_optional_time||epoch_millis"
                        }
                    }
                },
                "last_updated_milli":{  
                    "type":"long"
                },
                "last_updated_s":{  
                    "type":"date",
                    "format":"strict_date_optional_time||epoch_millis"
                },
                "name":{  
                    "type":"string",
                    "fields": {
                        "raw": { 
                            "type":  "string",
                            "index": "not_analyzed"
                        } 
                    }
                },
                "related_actor":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "related_element_choices":{  
                    "properties":{  
                        "display_text":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "value":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        }
                    }
                },
                "related_report":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
                "related_ttp":{  
                    "properties":{  
                        "elements":{  
                            "type":"string",
                            "index" : "not_analyzed"
                        },
                        "id":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        },
                        "name":{  
                            "type":"string",
                            "fields": {
                                "raw": { 
                                    "type":  "string",
                                    "index": "not_analyzed"
                                } 
                            }
                        }
                    }
                },
            }
        }
    },
    "settings" : {
        "number_of_shards"   : 5,
        "number_of_replicas" : 1
    }
}

create_template(es,name=ES_PREFIX+'threat_ttps', body=mapping)




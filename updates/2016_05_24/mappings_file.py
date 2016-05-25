#!/usr/bin.env python3.4
#the new templates for the editors field

def get_actor_mapping(ES_PREFIX):
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

    return mapping

def get_report_mapping(ES_PREFIX):
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

    return mapping

def get_ttp_mapping(ES_PREFIX):
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
                        "type": "long"
                    },
                    "description":{  
                        "type": "string"
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

    return mapping
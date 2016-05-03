#!/usr/bin/env python3.4
# Creates ES indexes for the threat actor application

from elasticsearch import Elasticsearch
from elasticsearch import exceptions
from elasticsearch.helpers import bulk

import time
import logging 

es_logger = logging.getLogger('elasticsearch')
es_logger.propagate = False
es_logger.setLevel(logging.DEBUG)
es_logger_handler=logging.StreamHandler()
es_logger.addHandler(es_logger_handler)

es_tracer = logging.getLogger('elasticsearch.trace')
es_tracer.propagate = False
es_tracer.setLevel(logging.INFO)
es_tracer_handler=logging.StreamHandler()
es_tracer.addHandler(es_tracer_handler)

ES_PREFIX = "tp-"

es = Elasticsearch(['http://localhost',])


data_simple = {}

data_simple['classification']           =   [
                                                "Nation State", 
                                                "Criminal", 
                                                "Hacktivist"
                                        ]

data_simple['motivation']               =   [
                                                "Espionage", 
                                                "Deny, degrade, disrupt, destroy, manipulate info or info systems"                                
                                        ]

data_simple['communication']            =   [
                                                "Jabber", 
                                                "ICQ", 
                                                "Email"
                                        ]

data_simple['country']                  =   [
                                                "China", 
                                                "Russia"                                
                                        ]



data_simple['financial']                =   [
                                                "Bitcoin Wallet", 
                                                "Bank Account", 
                                                "Credit Card"
                                        ]

data_simple['known_target']             =   [
                                                "Healthcare Industry",
                                                "Pharmaceutical Industry",
                                                "Hospitals", 
                                                "Biochemical Engineering Companies"
                                        ]


'''
data_simple['ttp']                      =   [
                                                "Watering Hole Attack", 
                                                "Spear Phishing", 
                                                "Adobe 0-Days",
                                                "Cyber Pathogens",
                                                "Metasploit",
                                                "Lateral Movement",
                                                "Generic Decoy Malware"
                                        ]
'''

data_simple['infrastructure_action']    =   [ 
                                                "Passive Only: Only passive requests shall be performed to avoid detection by the adversary", 
                                                "Take Down: Take down requests can be performed to avoid detection by the adversary", 
                                                "Monitoring Active: Monitoring requests are ongoing the adversary infrastructure", 
                                                "Pending Law Enforcement Request: Requests are ongoing the adversary infrastructure"
                                        ]

data_simple['infrastructure_owner']     =   [
                                                "Unknown: Infrastructure ownership and status is unknown", 
                                                "Compromised: Infrastructure compromised by or in the benefit of the adversary",
                                                "Own-and-Operated: Infrastructure owned and operated by adversary"
                                        ]

data_simple['infrastructure_status']    =   [
                                                "Unknown: Infrastructure state is unknown or can't be evaluated",
                                                "Active: Infrastructure state is active and actively being used by adversary",
                                                "Down: Infrastructure state is known to be down.",
                                        ]

data_simple['infrastructure_type']     =   [
                                                "Unknown: Infrastructure usage by the adversary is unknown",
                                                "Proxy: Infrastructure used as proxy between the target and the adversary",
                                                "Drop-Zone: Infrastructure used by the adversary to store information related to his campaigns",
                                                "Exploit-Distribution Point: Infrastructure used to distribute exploit towards target(s)",
                                                "Virtual Private Network (VPN): Infrastructure used by the adversary as VPN to hide activities and reduce traffic",
                                                "Panel: Panel used by adversary to control or maintain his infrastructure",
                                                "Traffic Distribution Systems (TDS): TDS including exploit delivery and/or web monetization channels"                      
                                        ]

data_simple['detection_rule']          =   [
                                                "Snort",
                                                "Yara"
                                        ]

data_pc = {}

#tpx classifications
data_pc['tpx_classification'] = [
    {
        "parent" : "Malware",
        "child" : "APT",
        "score" :  90
    },
    {
        "parent" : "Malware",
        "child" : "Adware",
        "score" :  40
    },
    {
        "parent" : "Malware",
        "child" : "Ransomware",
        "score" :  70
    },
    {
        "parent" : "Malware",
        "child" : "Web Shell",
        "score" :  65
    },
    {
        "parent" : "Malware",
        "child" : "Remote Access Trojan",
        "score" :  80
    },
    {
        "parent" : "Malware",
        "child" : "Rogue Antivirus",
        "score" :  40
    },
    {
        "parent" : "Malware",
        "child" : "Worm",
        "score" :  60
    },
    {
        "parent" : "Malware",
        "child" : "Rootkit",
        "score" :  60
    },
    {
        "parent" : "Malware",
        "child" : "Exploit Kit",
        "score" :  50
    },
    {
        "parent" : "Malware",
        "child" : "Automatic Transfer System",
        "score" : 80
    },
    {
        "parent" : "Malware",
        "child" : "Malware Artifacts",
        "score" :  30
    },
    {
        "parent" : "Malware",
        "child" : "Dialer",
        "score" :  40
    },
    {
        "parent" : "Malware",
        "child" : "Credential Theft",
        "score" :  60
    },
    {
        "parent" : "Malware",
        "child" : "DDoS",
        "score" :  60
    },
    {
        "parent" : "Malware",
        "child" : "Downloader",
        "score" : 30
    },
    {
        "parent" : "Malware",
        "child" : "Spam",
        "score" :  5
    },
    {
        "parent" : "Malware",
        "child" : "Click Fraud",
        "score" :  40
    },
    {
        "parent" : "Malware",
        "child" : "Financial",
        "score" :  60
    },
    {
        "parent" : "Malware",
        "child" : "Participant",
        "score" :  60
    },
    {
        "parent" : "Malware",
        "child" : "Script",
        "score" :  10
    },
    {
        "parent" : "Malware",
        "child" : "Stress Test Tool",
        "score" :  60
    },
    {
        "parent" : "Malware",
        "child" : "POS - ATM",
        "score" :  75
    },
    {
        "parent" : "Malware",
        "child" : "Spyware",
        "score" :  40
    },
    {
        "parent" : "Malicious",
        "child" : "Email",
        "score" :  15
    },
    {
        "parent" : "Malicious",
        "child" : "Password cracking",
        "score" :  40
    },
    {
        "parent" : "Malicious",
        "child" : "backdoor",
        "score" :  60
    },
    {
        "parent" : "Malicious",
        "child" : "SMTP Abuse",
        "score" :  20
    },
    {
        "parent" : "Malicious",
        "child" : "DNS",
        "score" :  60
    },
    {
        "parent" : "Malicious",
        "child" : "BGP",
        "score" :  60
    },
    {
        "parent" : "Malicious",
        "child" : "Russian Business Network",
        "score" :  20
    },
    {
        "parent" : "Recon",
        "child" : "Port Scanner",
        "score" :  20
    },
    {
        "parent" : "Recon",
        "child" : "Scanning",
        "score" :  30
    },
    {
        "parent" : "Recon",
        "child" : "Probes",
        "score" :  30
    },
    {
        "parent" : "Recon",
        "child" : "Vulnerability Scanner",
        "score" : 40
    },
    {
        "parent" : "Attack",
        "child" : "Bruteforce",
        "score" :  30
    },
    {
        "parent" : "Attack",
        "child" : "Sending Spam",
        "score" :  20
    },
    {
        "parent" : "Attack",
        "child" : "DDoS",
        "score" :  60
    },
    {
        "parent" : "Attack",
        "child" : "Phishing",
        "score" :  50
    },
    {
        "parent" : "Attack",
        "child" : "Malicious Email",
        "score" :  15
    },
    {
        "parent" : "Attack",
        "child" : "Hacktivism",
        "score" :  40
    },
    {
        "parent" : "Attack",
        "child" : "Hijack",
        "score" :  60
    },
    {
        "parent" : "Attack",
        "child" : "Exploit Kit",
        "score" :  50
    },
    {
        "parent" : "Attack",
        "child" : "Malvertising",
        "score" :  40
    },
    {
        "parent" : "Attack",
        "child" : "DoS",
        "score" :  60
    },
    {
        "parent" : "Infrastructure",
        "child" : "Education",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Corporate",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Public",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Transparent",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Hosting",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "AOL",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Exit Node",
        "score" :  50
    },
    {
        "parent" : "Infrastructure",
        "child" : "VPN",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "I2P",
        "score" : 5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Web Panel",
        "score" :  75
    },
    {
        "parent" : "Infrastructure",
        "child" : "Dynamic DNS",
        "score" :  10
    },
    {
        "parent" : "Infrastructure",
        "child" : "Legitimate Domain Registration Services",
        "score" :  1
    },
    {
        "parent" : "Infrastructure",
        "child" : "Malicious Domain Registrars",
        "score" :  20
    },
    {
        "parent" : "Infrastructure",
        "child" : "Top-Level Domain Registrars",
        "score" :  1
    },
    {
        "parent" : "Infrastructure",
        "child" : "Bulletproof Hosting/Rogue Hosting",
        "score" : 40
    },
    {
        "parent" : "Infrastructure",
        "child" : "Cloud Hosting",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Compromised Server",
        "score" :  40
    },
    {
        "parent" : "Infrastructure",
        "child" : "Fast Flux Botnet Hosting",
        "score" :  60
    },
    {
        "parent" : "Infrastructure",
        "child" : "Electronic Payment Methods",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Forums",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "IRC",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Jabber",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "P2P",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Mobile Communications",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Social Networks",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "User-Generated Content Websites",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Sinkhole",
        "score" :  5
    },
    {
        "parent" : "Infrastructure",
        "child" : "Illegal Activity",
        "score" :  15
    },
    {
        "parent" : "Infrastructure",
        "child" : "SCADA",
        "score" :  75
    },
    {
        "parent" : "Infrastructure",
        "child" : "Darknet",
        "score" :  20
    },
    {
        "parent" : "Intel",
        "child" : "Threat Report",
        "score" :  70
    },
    {
        "parent" : "Intel",
        "child" : "Campaign Characteristics",
        "score" :  70
    },
    {
        "parent" : "Intel",
        "child" : "Endpoint Characteristics",
        "score" :  40
    },
    {
        "parent" : "Intel",
        "child" : "Vulnerable Service",
        "score" : 40
    },
    {
        "parent" : "Intel",
        "child" : "Host Characteristics",
        "score" :  40
    },
    {
        "parent" : "Intel",
        "child" : "Infrastructure",
        "score" :  10
    },
    {
        "parent" : "Intel",
        "child" : "TTP",
        "score" :  70
    },
    { 
        "parent" : "Intel",
        "child" : "Collective Threat Intel",
        "score" :  70
    },
    {
        "parent" : "Intel",
        "child" : "Threat Actor Characterization",
        "score" :  70
    },
    {
        "parent" : "Observed Actions",
        "child" : "Exfiltration",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Brand or Image Degradation",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Economic",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Military",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Political",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Data Breach or Compromise",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Degradation of Service",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Destruction",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Disruption of Service",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Financial Loss",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Proprietary Information",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Intellectual Property",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Confidential Information",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Regulatory, Compliance or Legal Impact",
        "score" : 75
    },
    {
        "parent" : "Observed Actions",
        "child" : "Unintended Access",
        "score" :  75
    },
    {
        "parent" : "Observed Actions",
        "child" : "User Data Loss",
        "score" :  75
    },
    {
        "parent" : "Watchlist",
        "child" : "Domain Watchlist",
        "score" :  30
    },
    {
        "parent" : "Watchlist",
        "child" : "File hash watchlist",
        "score" :  30
    },
    {
        "parent" : "Watchlist",
        "child" : "IP Watchlist",
        "score" :  30
    },
    {
        "parent" : "Watchlist",
        "child" : "URL Watchlist",
        "score" :  30
    },
    {
        "parent" : "Actors",
        "child" : "APT",
        "score" :  90
    },
    {
        "parent" : "Actors",
        "child" : "Gray hat",
        "score" :  30
    },
    {
        "parent" : "Actors",
        "child" : "Black hat",
        "score" :  60
    },
    {
        "parent" : "Actors",
        "child" : "Hacktivist",
        "score" : 60
    },
    {
        "parent" : "Actors",
        "child" : "White hat",
        "score" :  5
    },
    {
        "parent" : "Actors",
        "child" : "State Actor or Agency",
        "score" :  85
    },
    {
        "parent" : "Actors",
        "child" : "Underground Call Service",
        "score" :  60
    },
    {
        "parent" : "Actors",
        "child" : "Spam Service",
        "score" :  20
    },
    {
        "parent" : "Actors",
        "child" : "Credential Theft Botnet Operator",
        "score" :  50
    },
    {
        "parent" : "Actors",
        "child" : "Credential Theft Botnet Service",
        "score" :  50
    },
    {
        "parent" : "Actors",
        "child" : "Malware Developer",
        "score" :  60
    },
    {
        "parent" : "Actors",
        "child" : "Money Laundering Network",
        "score" :  40
    },
    {
        "parent" : "Actors",
        "child" : "Organized Crime Actor",
        "score" :  60
    },
    {
        "parent" : "Actors",
        "child" : "Traffic Service",
        "score" :  30
    },
    {
        "parent" : "Actors",
        "child" : "Insider Threat",
        "score" :  75
    },
    {
        "parent" : "Actors",
        "child" : "Disgruntled User",
        "score" :  75
    },
    {
        "parent" : "Actors",
        "child" : "Jihadist",
        "score" :  75
    },
    {
        "parent" : "Actors",
        "child" : "White Supremacist",
        "score" : 65
    },
    {
        "parent" : "Actors",
        "child" : "Cyber Espionage Operations",
        "score" : 99
    },
    {
        "parent" : "Actors",
        "child" : "Malware Developer",
        "score" : 60
    },
    {
        "parent" : "Actors",
        "child" : "CBRN Chemical, biological, radiological and nuclear",
        "score" : 75
    }
]


'''
Example Pull
'''
def insert_bulk(docs):
    results = bulk(es, docs, raise_on_error=False, raise_on_exception=False)
    for error in results[1]:
        try:
            m = error['create']['error']['caused_by']['type']
        except:
            try:
                m = error['create']['error']['type']
            except Exception as e1:
                print(error)
                print(str(e1))

bulk_docs = []
for k,v in data_simple.items():
    for i in v:
        my_id = k.strip() + " " + i.strip()
        source = { 
            'value' :   i.strip(),
            'type'  :   k.strip()
        }

        #print(es.index(ES_PREFIX + 'threat_actor_simple','data',source,my_id))
        
        action = {
            "_op_type"  :   "create", 
            "_index"    :   ES_PREFIX + 'threat_actor_simple',
            "_type"     :   "data",
            "_id"       :   my_id,
            "_source"   :   source
        }
        bulk_docs.append(action)

        if len(bulk_docs) > 100:
            insert_bulk(bulk_docs)
            bulk_docs = []
        

for k,v in data_pc.items():
    for d in v:

        parent_id = k.strip() + " " + d['parent'].strip()
        parent = {
            'value' : d['parent'].strip(),
            'type' : k
        }
        parent_action = {
            "_op_type"  :   "create", 
            "_index"    :   ES_PREFIX + 'threat_actor_pc',
            "_type"     :   "parent",
            "_id"       :   parent_id, 
            "_source"   :   parent
        }
        bulk_docs.append(parent_action)

        my_id = parent_id.strip() + " " + d['child'].strip()
        source = { 
            'value' :   d['child'].strip(),
            'score' :   d['score']
        }

        action = {
            "_op_type"  : "create", 
            "_index"    : ES_PREFIX + 'threat_actor_pc',
            "_type"     : "child",
            "_id"       : my_id,
            "_parent"   : parent_id,
            "_source"   : source
        }
        bulk_docs.append(action)

        if len(bulk_docs) > 100:
            insert_bulk(bulk_docs)
            bulk_docs = []

if len(bulk_docs) > 0:
    insert_bulk(bulk_docs)
    bulk_docs = []

'''
Example Pull
'''

'''
body = {
    "query" : {
        "term" : {
            "type" : "ttp"
        }
    },
    "sort": {
        "value": {
            "order": "asc"
        }
    }
}

results = es.search(ES_PREFIX + 'threat_actor_simple', 'data', body)
d = []
for r in results['hits']['hits']:
    d.append(r['_source']['value'])
'''


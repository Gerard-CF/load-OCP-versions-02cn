#!/usr/bin/env python3

import redis
import os, json, urllib, requests, time, string, ast, logging, random
from logging.config import dictConfig
from logdna import LogDNAHandler

def getRequestId():
    letters = string.ascii_uppercase
    return ''.join(random.choice(letters) for i in range(6))

def getiamtoken(apikey):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic Yng6Yng=',
    }
    parms = {"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": apikey}

    try:
        resp = requests.post(os.environ.get('IAM_ENDPOINT') + "/identity/token?" + urllib.parse.urlencode(parms), headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        quit()
    except requests.exceptions.Timeout as errt:
        quit()
    except requests.exceptions.HTTPError as errb:
        quit()
    iam = resp.json()
    return iam  

def getRedisCert(reqid, apikey):
    logger.debug("{} Starting to get Redis Certificate ")
    iamToken = getiamtoken(apikey)
    certManagerEndpoint = os.environ.get('CERT_MANAGER_ENDPOINT')
    header = {
        'accept': 'application/json',
        'Authorization': 'Bearer ' + iamToken["access_token"]
    }
    redis_crn = os.environ.get('REDIS_CERT_CRN')
    url = certManagerEndpoint+'/api/v2/certificate/'+urllib.parse.quote_plus(redis_crn)
    
    response = requests.get(url,headers=header)
    json_response = json.loads(response.text)
    cert_file = open("redis-crt.pem", "wt")
    n = cert_file.write(json_response['data']['content'])
    cert_file.close()
    
    return

def loadOCPCache():
    try:
        reqid = getRequestId()
        logger.info("{} Starting to load ROKS Versions Cache".format(reqid))
        apikey = os.environ.get('IBMCLOUD_APIKEY')
        redisCert = getRedisCert(reqid, apikey)
        r = redis.StrictRedis(
            host=os.environ.get('REDIS_HOST'), 
            port=os.environ.get('REDIS_PORT'), 
            password=os.environ.get('REDIS_PASSWORD'),
            ssl=True,
            ssl_ca_certs='redis-crt.pem',
            db=0,
            decode_responses=True)

        getVersionUrl="https://containers.cloud.ibm.com/global/v2/getVersions"
        headers = { "Content-Type": "application/json" } 
        # try to call the api twice
        try:
            resp = requests.get(getVersionUrl, headers=headers)
            oc_versions = resp.json()["openshift"]
        except:
            resp = requests.get(getVersionUrl, headers=headers)
            oc_versions = resp.json()["openshift"]
        returned_versions = []
        for version in oc_versions:
            major = version["major"]
            minor = version["minor"]
            patch = version["patch"]
            version_to_add=str(major)+"."+str(minor)+"."+str(patch)+"_openshift"
            logger.debug("{} going to add openshift version {}".format(reqid, version_to_add))
            returned_versions.append(version_to_add) 
        r.set("openshift_versions", str(returned_versions))
    except Exception as e:
        print(e)
        logger.error("{} Error - loading OCP Versions {}".format(reqid, e))
        

if __name__ == '__main__':
    try:
        dictConfig({
            'version': 1,
            'formatters': {
                'default': {
                    'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
                }
            },
            'handlers': {
                'logdna': {
                    'level': logging.DEBUG,
                    'class': 'logging.handlers.LogDNAHandler',
                    'key': os.environ.get('LOGDNA_APIKEY'),
                    'options': {
                        'app': 'load-ocp-versions-02cn.py',
                        'tags': os.environ.get('SERVERNAME'),
                        'env': os.environ.get('ENVIRONMENT'),
                        'url': os.environ.get('LOGDNA_LOGHOST'),
                        'index_meta': True,
                    },
                 },
            },
            'root': {
                'level': logging.DEBUG,
                'handlers': ['logdna']
            }
        })
        logger = logging.getLogger('logdna')
        loadOCPCache()
    except Exception as e:
        print("error"+str(e))

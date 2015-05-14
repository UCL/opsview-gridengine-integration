# Copyright (c) 2013, UCL
# All rights reserved.

# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided 
# with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN 
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# Author: Francesco Tusa


#!/usr/bin/python

import sys, urllib, urllib2, getopt, datetime, logging
import simplejson as json, pprint



def SetLogger(logfile, loglevel, runForeground):
    global logger 
    logger = logging.getLogger('RESTOpsview')
    logger.setLevel(loglevel)
    frmt = logging.Formatter('%(module)s - %(asctime)s - %(levelname)s: %(message)s')

    if not runForeground:
       fh = logging.FileHandler(logfile)
    else:
       fh = logging.StreamHandler()

    fh.setFormatter(frmt)
    logger.addHandler(fh)
    return fh

    

def opsviewAuthentication(opsview_url='http://mon02.external.legion.ucl.ac.uk:3000/', opsview_user = 'admin', opsview_password = 'M4Jd+jcQ'):
    '''creates a connection to the opsview server and allow authentication with the provided credentials. The three returned parameters 
       have to be used for subsequent interactions with the server'''

    logger.info('Authenticating to the Opsview server %s', opsview_url)

    try:
       ops_cookies = urllib2.HTTPCookieProcessor()
       ops_opener = urllib2.build_opener(ops_cookies)
       ops = ops_opener.open(
                             urllib2.Request(opsview_url + "rest/login",
                             urllib.urlencode(dict(
                                                   {
                                                   'username': opsview_user,
                                                   'password': opsview_password,
                                                   }
                                                  )
                                             )
                                            )
                            )

       response_text = ops.read()
       response = eval(response_text)


    except urllib2.URLError, e:
       logger.error('Error while connecting to the server %s. %s', opsview_url, e)
       sys.exit(-3)

    if not response:
       logger.error('Cannot evaluate %s"', response_text)
       return -1

    if "token" in response:
       logger.info('OPSView authentication succeeded')
       logger.debug('Token: %s', response['token'])
       ops_token = response["token"]

       headers = {
           "Content-Type": "application/json",
           "X-Opsview-Username": opsview_user,
           "X-Opsview-Token": ops_token,
       }
       return opsview_url, headers, ops_opener
    else:
       logger.error('OPSView authentication FAILED')
       return -2



def deleteHostService(opsview_url, headers, ops_opener, hostName, serviceToDeleteName):
    ''' deletes a servicecheck whose name is provided as parameter serviceToDeleteName
        from the host identified by hostName in Opsview'''

    #retrieving information for host hostName and storing them as json object
    logger.info('Deleting service %s from host %s', serviceToDeleteName, hostName)
    url = opsview_url + 'rest/config/host?json_filter={"name":{"-like":"' + hostName + '"}}'
    request = urllib2.Request(url, None, headers)

    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Retrieved Host information %s\n:', jdata)

    except urllib2.URLError, e:
        logger.error('Cannot list existing services. %s: %s', e.code, e.read())
        sys.exit(-1)
  
    #looking for the json element to delete
    for i, service in enumerate(jdata['list'][0]['servicechecks']):
        if serviceToDeleteName in service['name']:
           del jdata['list'][0]['servicechecks'][i]

    #updating host information, using PUT (POST didn't work)
    url = opsview_url + 'rest/config/host/'
    request = urllib2.Request(url, json.dumps(jdata), headers)
    request.get_method = lambda:'PUT'

    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Host updating: \n%s', jdata)

    except urllib2.URLError, e:
        logger.error('Cannot update host %s. %s: %s', hostName, e.code, e.read())



def fetchServerInfo(opsview_url, headers, ops_opener):
    # Fetch server info
    url = opsview_url + "rest/serverinfo"
    request = urllib2.Request(url, None, headers)
    logger.debug(ops_opener.open(request).read())



def retrieveExistingServices(opsview_url, headers, ops_opener):
    
    #retrieving services for the SGE group (45)   
    url = opsview_url + "rest/config/servicegroup/45"
    request = urllib2.Request(url, None, headers)
    existingServices = []   

    logger.info('Retrieving information from Opsview about all the defined service checks')
 
    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())

        #filtering load sensors from the retrieved object and 
        #storing them into the existingServices list
        for serviceName in jdata['object']['servicechecks']:
            #Sun Grid Engine is not a load sensor: discarding it
            if 'Sun Grid Engine' not in serviceName['name']:
               existingServices.append(serviceName['name'])
        logger.debug('Services defined into Opsview: %s', pprint.pformat(existingServices))    
        return existingServices
    
    except urllib2.URLError, e:
        logger.debug('Cannot list existing services. %s: %s', e.code, e.read())
        sys.exit(-1)



def retrieveHostsServices(opsviewDict, opsview_url, headers, ops_opener):

    #retrieving Host services for all the nodes   
    url = opsview_url + 'rest/config/host?rows=all'
    logger.info('Retrieving services information from Opsview for all the hosts')
   
    request = urllib2.Request(url, None, headers)
    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Existing services:\n %s', pprint.pformat(jdata))

    except urllib2.URLError, e:
        logger.error('Cannot list host services. %s: %s', e.code, e.read())
        sys.exit(-1)

    for host in jdata['list']:
        opsviewDict[host['name']]=host
    logger.debug('opsviewDict:\n %s', pprint.pformat(opsviewDict))



def modifyHostsServices(opsviewDict, opsview_url, headers, ops_opener):
    url = opsview_url + 'rest/config/host'    
    request = urllib2.Request(url, json.dumps(opsviewDict), headers)
    request.get_method = lambda:'PUT'

    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Opsview response to the host service update request:\n %s',pprint.pformat(jdata))
    except urllib2.URLError, e:
        logger.error('Cannot update host services. %s: %s',e.code, e.read())
        sys.exit(-1)



def cloneHost(opsview_url, headers, ops_opener, hostName, ip, group, hostToCloneId='2'):
    logger.info('cloning host with id %s to host %s', hostToCloneId, hostName)
    logger.debug('opsview_url: %s', opsview_url)
    logger.debug('hostToCloneId: %s', hostToCloneId)
    url = opsview_url + 'rest/config/host/' + hostToCloneId
    logger.debug('URL: %s', url)
    logger.debug('Headers: %s', headers)
    request = urllib2.Request(url, None, headers)
    logger.debug('About to request host template: %s', hostToCloneId)
    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Host template: \n%s', jdata)

    except urllib2.URLError, e:
        logger.error('Could not get host template. %s: %s', e.code, e.read())

    del jdata['object']['id']
    del jdata['object']['keywords']
 
    jdata['object']['name']=hostName
    jdata['object']['ip']=ip
    jdata['object']['hostgroup']['name']=group

    #posting the host template as new host
    url = opsview_url + 'rest/config/host/'
    request = urllib2.Request(url, json.dumps(jdata), headers)

    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Host cloning: \n%s', jdata)

    except urllib2.URLError, e:
        logger.error('Cannot clone host %s. %s: %s', hostName, e.code, e.read())



def cloneService(opsview_url, headers, ops_opener, serviceName, serviceToCloneId='224'):
    #getting the json object for service node temperature and using it as service template
    url = opsview_url + 'rest/config/servicecheck/' + serviceToCloneId
    request = urllib2.Request(url, None, headers)

    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Service template: \n%s', jdata)

    except urllib2.URLError, e:
        logger.error('Could not get host template. %s: %s', e.code, e.read())

    #removing some fields from the template: id
    del jdata['object']['id']

    #modifying some relevant information for the new service to add: name 
    jdata['object']['name']=serviceName
    jdata['object']['description']='Checks node\'s ' + serviceName + ' through NSCA'

    #putting the service template as new servicecheck
    url = opsview_url + 'rest/config/servicecheck/'
    request = urllib2.Request(url, json.dumps(jdata), headers)

    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Service cloning: \n%s', jdata)

    except urllib2.URLError, e:
        logger.debug('Cannot clone service %s. %s: %s', serviceName, e.code, e.read())



def checkGroup(opsview_url, headers, ops_opener, groupName, groupToCloneId='4'):
    #getting the json object for service node temperature and using it as service template
    url = opsview_url + 'rest/config/hostgroup/?json_filter={"name":{"-like":"' + groupName  + '"}}'
    request = urllib2.Request(url, None, headers)
    logger.info('checking existance of group %s', groupName)
    
    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Hostgroup template: \n%s', jdata)

    except urllib2.URLError, e:
        logger.error('Could not get hostgroup template. %s: %s', e.code, e.read())

    if len(jdata['list']) == 0:
       #getting template
       url = opsview_url + 'rest/config/hostgroup/' + groupToCloneId
       request = urllib2.Request(url, None, headers)
  
       try:
           ops = ops_opener.open(request)
           jdata = json.loads(ops.read())
           logger.debug('Hostgroup template: \n%s', jdata)

       except urllib2.URLError, e:
           logger.error('Could not get hostgroup template. %s: %s', e.code, e.read())

       del jdata['object']['id']
       del jdata['object']['hosts']
       del jdata['object']['is_leaf']
       jdata['object']['name'] = groupName
  
       #creating new group
       url = opsview_url + 'rest/config/hostgroup/'
       request = urllib2.Request(url, json.dumps(jdata), headers)
       logger.info('group %s does not exist - creating it', groupName)

       try:
           ops = ops_opener.open(request)
           jdata = json.loads(ops.read())
           logger.debug('Host group cloning: \n%s',jdata)

       except urllib2.URLError, e:
           logger.error('Cannot clone  host group %s. %s: %s', groupName, e.code, e.read())

    logger.debug('Leaving checkGroup')



def deleteService(opsview_url, headers, ops_opener, serviceToDeleteName):
    
    url = opsview_url + 'rest/config/servicegroup/45'
    request = urllib2.Request(url, None, headers)
       
    try:  
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Services: \n%s', jdata['object']['servicechecks'])
    
    except urllib2.URLError, e:
        logger.error('Cannot get host template. %s: %s', e.code, e.read())

    for service in jdata['object']['servicechecks']:
        if serviceToDeleteName in service['name']:
           serviceToDeleteInfo = service

    #updating services group information, using DELETE
    url = opsview_url + serviceToDeleteInfo['ref'][1:]
    request = urllib2.Request(url, None, headers)
    request.get_method = lambda:'DELETE'

    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Services group updating: \n%s', jdata)

    except urllib2.URLError, e:
        logger.error('Cannot update service group info. %s: %s', e.code, e.read())



def deleteHost(opsview_url, headers, ops_opener, hostToDeleteName):
    url = opsview_url + 'rest/config/host?json_filter={"name":{"-like":"' + hostToDeleteName  + '"}}'
    request = urllib2.Request(url, None, headers)
    logger.info('deleting host %s', hostToDeleteName)
    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Host to delete: \n%s', jdata)

    except urllib2.URLError, e:
        logger.error('Cannot get host to delete information. %s: %s', e.code, e.read())

    #deleting host
    url = opsview_url + 'rest/config/host/' + jdata['list'][0]['id']
    request = urllib2.Request(url, None, headers)
    request.get_method = lambda:'DELETE'

    try:
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())
        logger.debug('Deleting host: \n%s', jdata)

    except urllib2.URLError, e:
        logger.error('Cannot delete host. %s: %s', e.code, e.read())



def reloadConfiguration(opsview_url, headers, ops_opener):
    url = opsview_url + 'rest/reload'
    request = urllib2.Request(url, None, headers)

    try:
        logger.info('Checking Opsview server status')
        ops = ops_opener.open(request)
        jdata = json.loads(ops.read())

    except urllib2.URLError, e:
        logger.error('Cannot retrieve server status %s: %s',e.code, e.read())

    if '0' in jdata['server_status']:
       logger.info('Server status is OK - Starting the configuration update')
       request = urllib2.Request(url, None, headers)
       request.get_method = lambda:'POST'
       try:
          ops = ops_opener.open(request)
          jdata = json.loads(ops.read())
          if '0' in jdata['server_status']:
             logger.info('Configuration update completed successfully')
          else:
             logger.error('Opsview server in a bad status. server_status: %s', jdata['server_status'])

       except urllib2.URLError, e:
        logger.error('Cannot start configuration update %s: %s', e.code, e.read())

    else:
       logger.error('Opsview server in a bad status! server_status %s',jdata['server_status'])
       return -1 

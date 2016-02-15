#!/usr/bin/python

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


import subprocess, shlex, pprint, sys, os, getopt, datetime, logging, daemon, time, threading, socket, re
import simplejson as json
import opsviewREST as rest

SGE_ROOT='/opt/sge'

def generateNSCAMessages(nodesSensorsDataDict, nodesOpsviewDataDict, hostsGroup, commandPath='/usr/local/nagios/bin/send_nsca', serverName='mon02.data.legion.ucl.ac.uk', configFile='/usr/local/nagios/etc/send_nsca.cfg'):
    'generates passive alerts considering the dictionaries filled up by checkNodesState()'

    messagesDict = { '-1' : 'u(ncontactable)', '-2' : 'E(rror)', '-3' : 'c(onfiguration error)', '-255' : 'no value'}
    for group in hostsGroup.keys():
        logger.info('Sending messages to the Opsview server ' + serverName + ' through NSCA for group %s', group)
        messageToSend=''

        for currentNode in hostsGroup[group].split():
            if currentNode in nodesSensorsDataDict.keys():
               for currentSensor in nodesOpsviewDataDict[currentNode].keys():
                   if str(nodesSensorsDataDict[currentNode][currentSensor][0]) in messagesDict.keys():
                      message=currentNode + '\t' + currentSensor + '\t' + str(nodesOpsviewDataDict[currentNode][currentSensor]) + '\t' + 'queue status: ' + messagesDict[str(int(nodesSensorsDataDict[currentNode][currentSensor][0]))] + '\n'
                   else:
                      #message=currentNode + '\t' + currentSensor + '\t' + str(nodesOpsviewDataDict[currentNode][currentSensor]) + '\t' + 'qstat collected value: ' + str(nodesSensorsDataDict[currentNode][currentSensor][0]) + '\n'
                      message=currentNode + '\t' + currentSensor + '\t' + str(nodesOpsviewDataDict[currentNode][currentSensor]) + '\t' + str(nodesSensorsDataDict[currentNode][currentSensor][0])  + ' |' + currentSensor + '=' + str(unit_convert(nodesSensorsDataDict[currentNode][currentSensor][0])) + '\n'
                   messageToSend= messageToSend + message

        logger.debug(messageToSend)
        sendCommand='/bin/echo -e "' + messageToSend + '" | ' + commandPath + ' ' + serverName + ' -c ' + configFile
        exitCode = subprocess.call(sendCommand, shell=True)
        if exitCode == 0:
           logger.info('Information sent to the Opsview server %s for group %s - sleep 10', serverName, group)
           time.sleep(10)
        else:
           logger.error('Error while sending information to the Opsview server %s for group %s', serverName, group)



def checkCmpOperations(operation):
    'checks if the alarm condition is valid'
    if operation in ['<=','==','>=']: return operation
    else: return -1



def checkNodesState(loadSensorsDataDict,nodesSensorsDataDict,hostSensorsDict,warning=0.85):
    '''checks the dictionary containing the hosts information and generates the output for Nagios/Opsview
       the third parameter warning is not currently being used because we're not generating warning for load sensor values
       close to the threshold'''

    logger.info('Checking alarm conditions on the retrieved data')

    nodesOpsviewDataDict = dict()

    for currentNode in nodesSensorsDataDict.keys():               
        if currentNode not in nodesOpsviewDataDict.keys(): nodesOpsviewDataDict[currentNode]=dict()
        for currentSensor in loadSensorsDataDict.keys():
            validAlarmCondition=checkCmpOperations(loadSensorsDataDict[currentSensor][0])
            if validAlarmCondition>0:
               if currentSensor in hostSensorsDict[currentNode].keys():
                  #logger.debug('current node: %s, current sensor: %s, value: %s threshold: %s',currentNode,currentSensor,nodesSensorsDataDict[currentNode][currentSensor],loadSensorsDataDict[currentSensor][2])
                  exec(
                  #checking and set failure only for those values whose alarm condition is verified but in alarm state also in the SGE queue. Setting critical
                  "if unit_convert(nodesSensorsDataDict[currentNode][currentSensor][0]) " + validAlarmCondition + " unit_convert(hostSensorsDict[currentNode][currentSensor]) and len(nodesSensorsDataDict[currentNode][currentSensor])>1:\n" +
                  "   nodesOpsviewDataDict[currentNode][currentSensor]=2\n" +

                  #this implementation doesn't take care of values close to the threshold and doesn't generate warning for them
                  #"elif nodesSensorsDataDict[currentNode][currentSensor][0] " + validAlarmCondition +  " float(warning*loadSensorsDataDict[currentSensor][2]) and loadSensorsDataDict[currentSensor][1]!='INT':\n" +
                  #"     nodesOpsviewDataDict[currentNode][currentSensor]=1\n" +
               
                  #setting unknown for load sensors whose queues are uncontactable
                  # Now added a 'queuestatus' loadsensor if any of the queues are uncontactable...
                  #"elif nodesSensorsDataDict[currentNode][currentSensor][0]==-1:\n" +
                  #"     nodesOpsviewDataDict[currentNode][currentSensor]=3\n" +

                  ##setting warning for SGE unknown values (old implementation)
                  #"elif nodesSensorsDataDict[currentNode][currentSensor][0]==-1:\n" +
                  #"     nodesOpsviewDataDict[currentNode][currentSensor]=1\n" +

                  #setting warning for load sensors whose queues are in 'c' and 'E' states
                  "elif nodesSensorsDataDict[currentNode][currentSensor][0]==-2 or nodesSensorsDataDict[currentNode][currentSensor][0]==-3:\n" +
                  "     nodesOpsviewDataDict[currentNode][currentSensor]=1\n" +

                  #for now we are managing values not available after parsing qstat output as warnings (TODO: check if it is correct)
                  "elif nodesSensorsDataDict[currentNode][currentSensor][0]==-255:\n" +
                  "     nodesOpsviewDataDict[currentNode][currentSensor]=1\n" +

                  #setting OK for all the other cases
                  "else: nodesOpsviewDataDict[currentNode][currentSensor]=0\n"
                  )
            else:
                  raise UnboundLocalError('Cannot manage alarm condition: ', validAlarmCondition)

    logger.debug('Data that will be sending to Opsview: %s',nodesOpsviewDataDict)
    return nodesOpsviewDataDict



def generateGlobalSensorsList(hostsSensors):
    '''this function parses all the sensors defined for each host and creates a dictionary with all the globally defined load sensors'''    

    logger.info('Generating the list of all sensors defined into Opsview')
    globalSensors = dict()
    for currentHost in hostsSensors.keys():
        for currentSensor in hostsSensors[currentHost].keys():
            if currentSensor not in globalSensors.keys():
               logger.info('Adding sensor: %s to globalSensors.',currentSensor)
               globalSensors[currentSensor] = hostsSensors[currentHost][currentSensor]
    return globalSensors



def checkSensorsExistance(sensorsToCheck):
    '''checks if the tuple of sensors is valid through the qconf -sc command. This will generate an exception otherwise'''

    logger.info('Quering SGE for load sensors interesting parameters')

    #invoking the qconf program for retrieving the list of existing load_sensors
    getCommandArgs=SGE_ROOT+'/bin/lx-amd64/qconf -sc'
    getCommand = shlex.split(getCommandArgs)
    
    cmd = subprocess.Popen(getCommand, stdout=subprocess.PIPE)
    out = cmd.communicate()[0].split('\n')[2:-2]
    
    globalSensorsInfo=dict()

    #creating a list of all the existing load_sensors and other SGE stuff: collecting information about the check to be carried out
    for sensorLine in out: 
        sensorName=sensorLine.split()[0] #the load_sensor identifier

        if sensorName in sensorsToCheck.keys():
           sensorAlarmCondition=sensorLine.split()[3] #the alarm conditions
           sensorType=sensorLine.split()[2] #the sensors type (INT, FLOAT, etc.)
           sensorThreshold=sensorsToCheck[sensorName]
           #adding the current load sensor information to the dictionary
           globalSensorsInfo[sensorName]=[sensorAlarmCondition, sensorType, sensorThreshold]

    logger.debug('Load sensors information retrieved:\n %s', pprint.pformat(globalSensorsInfo))    
    return globalSensorsInfo



def getHostInfo(name):
    try:
        ip=socket.gethostbyname(name)
    except socket.gaierror, e:
           print 'Cannot resolve the host name provided - assigning fake IP to host %s' % name
           ip='none'

    #if 'usertest' in name:
    #   group='Usertest'
    group=name.split('-')[1]
    #elif not name.split('-')[1].isdigit():
    #     group='CU-' + name.split('-')[1][0].upper()
    #else:
    #     group = 'Serial' 
    return ip, group



def compareHosts(sgeHosts, opsviewHosts):
    comparison = {'add':[],
                  'del':[]
                 }
    
    for host in sgeHosts.keys():
        if host not in opsviewHosts.keys():
           comparison['add'].append(host)
        
    for host in opsviewHosts.keys():
        if host not in sgeHosts.keys() and ('node' in host or 'usertest' in host):
           comparison['del'].append(host)
    return comparison



def getHostsList():
    '''creates a list hostList with all the hosts retrieved from SGE'''    

    logger.info('Collecting the hosts list from SGE')

    getCommandArgs=SGE_ROOT+'/bin/lx-amd64/qconf -sel'
    getCommand = shlex.split(getCommandArgs)
    cmd = subprocess.Popen(getCommand, stdout=subprocess.PIPE)
    out = cmd.communicate()[0]

    hostList = []
    for currentHost in out.split('\n'):
        hostName = currentHost.split('.')[0]
        if 'node' in hostName or 'usertest' in hostName: hostList.append(hostName)
    
    logger.debug('Host list built through qconf -sel: %s\n',pprint.pformat(hostList))
    return hostList



def generateGroups(hostList):
    '''this function takes as input the list of all nodes defined into SGE and creates/returns a new nodesGroup dictionary with hosts grouped by the CU/type'''

    nodesGroup = dict()
    logger.info('Grouping hosts by CUs/groups')

    for host in hostList:
        try: 
           group = host.split('-')[1]
           if group not in nodesGroup.keys():
               nodesGroup[group] = host + ' '
           else:
               nodesGroup[group] += host + ' '
        except IndexError:
           logger.error('Invalid host: %s\n',host)

           #if not group.isdigit():
           #   if group not in nodesGroup.keys(): nodesGroup[group] = host + ' '
           #   else: nodesGroup[group] += host + ' '
           #else:
           #   if 'fatAndSerial' not in nodesGroup.keys(): nodesGroup['fatAndSerial'] = host + ' '
           #   else: nodesGroup['fatAndSerial'] += host + ' '

        #except IndexError:
        #   if 'usertest' not in nodesGroup.keys(): nodesGroup['usertest'] = host + ' '
        #   else: nodesGroup['usertest'] += host + ' '

    logger.info('Host groups:\n %s', pprint.pformat(nodesGroup))
    return nodesGroup 
 

def unit_convert(valueToConvert):
    if isinstance(valueToConvert, basestring):
       unit = valueToConvert[-1]
       if unit == 'T':
          value = long(float(valueToConvert[0:-1])*(1024**4))
       elif unit == 'G':
          value = long(float(valueToConvert[0:-1])*(1024**3))
       elif unit == 'M':
          value = long(float(valueToConvert[0:-1])*(1024**2))
       elif unit == 'K':
          value = long(float(valueToConvert[0:-1])*1024)
       elif unit.isdigit():
          value = long(float(valueToConvert))
       else:
           #we realized sometimes the value collected by a temperature load sensor is '(null)'
           #this caused crashes while trying to convert the value: creating a speciale case
           #and assigning a non-sensible temperature value
           if valueToConvert == '(null)':
              logger.warn('Null value to convert found --- Converting to -275')
              value = long(float(-275))
           else: # maybe this else is not needed  
              value = valueToConvert
       return value


def getNagtxt():
    ''' this function has been created to retrieve the complex settings.
        This is needed to select only those load sensors which have a corresponding
        _nagtxt entry in the complex. '''

    #invoking the qconf program for retrieving the list of existing load_sensors
    getCommandArgs=SGE_ROOT+'/bin/lx-amd64/qconf -sc'
    getCommand = shlex.split(getCommandArgs)
    cmd = subprocess.Popen(getCommand, stdout=subprocess.PIPE)
    out = cmd.communicate()[0].split('\n')[2:-2]
    validSensors=[]
    for line in out:
        if '_nagtxt' in line:
           validSensors.append(line.split()[0])
    return validSensors


def getSensorsInfo(hostGroup, hostsInfo, validSensors):
    '''creates a dictionary that describes how load sensors defined in SGE are mapped on the nodes'''
    
    logger.debug('Collecting sensors\' information from SGE for hosts: %s', hostGroup)

    getCommand='for host in ' + hostGroup + '; do echo "host $host"; SGE_SINGLE_LINE=true '+SGE_ROOT+'/bin/lx-amd64/qconf -sq  *@$host 2> /dev/null| grep load_thresholds; echo "---" | sort -u; done'

    cmd = subprocess.Popen(getCommand, stdout=subprocess.PIPE, shell=True)
    out = cmd.communicate()[0]
 
    for host in out.split('---'):
        hostThreshold = dict()
	#hostThreshold['load_avg']=100
        for line in host.split('\n'): 
            if 'host' in line: 
               hostName = line.split()[1]
            elif 'load_thresholds' in line and 'NONE' not in line:
               for currentThreshold in line.split()[1:]:
                   #This is for considering only those load sensors which have a corresponding _nagtxt in the complex 
                   #others load sensors don't need to be considered when alarmed as they are being used for implementing
                   #backfill jobs execution on reserved nodes
                   if currentThreshold.split('=')[0] not in hostThreshold.keys() and currentThreshold.split('=')[0]+'_nagtxt' in validSensors:
                      hostThreshold[currentThreshold.split('=')[0]] = currentThreshold.split('=')[1]
                      logger.debug('Sensor %s has a _nagtxt definition', currentThreshold.split('=')[0])

        if hostName not in hostsInfo.keys():
           hostsInfo[hostName] = hostThreshold



def parseHostsState(loadSensorsToMonitor):
    '''parses the output of the command qstat and creates a dictionary with all the hosts information
    loadSensorsToMonitor: contains a list of load_sensors to be monitored
    (alarm conditions, thresholds currently being retrieved from qstat)
    hosts_dict: will contain the data coming from the SGE load sensors'''

    hosts_dict = dict()

    logger.info('Collecting load sensors values from SGE')
    #invoking the qstat program for retrieving the nodes' state

    getCommandArgs=SGE_ROOT+'/bin/lx-amd64/qstat -explain a -F'
    getCommand = shlex.split(getCommandArgs)
    
    cmd = subprocess.Popen(getCommand, stdout=subprocess.PIPE)
    out = cmd.communicate()[0]

    #setting the hosts separator line
    hostList=out.split('-'*81)

    sensorsThresholdBuffer=dict()
    hostsQueuesState=dict() 

    #parsing information and storing the relevant load_sensors data for the current node: nodetemp, ibproblems and forecast
    for host in hostList:

        #resetting buffer variables for the corrent node
        currentNode=''        
        loadSensorsValues=dict()
        alarmedSensors=dict()
        unknownSensors=dict()

        for line in host.split('\n'):

            #check if the current line contains the hostname information
            if re.match('^[A-Za-z][a-z]*\@',line):
               if len(line.split()) > 5:
                  queueState = line.split()[-1]
               else:
                  queueState = 'n'

            elif 'qf:hostname=' in line:
	        currentNode = line.split('=')[1].split('.')[0]
 
            #collecting the threshold values and the alarmed sensors values and adding them to the associated dictionaries 
            elif 'alarm' in line and 'load-threshold' in line: #needed to check if the queue is not in u for forecast?
                 #splitting the line for retrieving sensors in alarm condition and their values
                 currentAlarmedSensor=line.split('=')[0].split(':')[1]
                 currentAlarmedSensorValueRaw=line.split('=')[1].split()[0]

                 if '-' in currentAlarmedSensorValueRaw:
                     logger.debug('---NEGATIVE---- %s', currentAlarmedSensorValueRaw)
                     currentAlarmedSensorValue=-1

                 else:
                    currentAlarmedSensorValue = currentAlarmedSensorValueRaw
                    
                 if currentAlarmedSensor not in alarmedSensors.keys():
                    alarmedSensors[currentAlarmedSensor]=currentAlarmedSensorValue

            elif 'error' in line and 'unknown' in line:
                 currentUnknownSensor=line.split(':')[1].split()[3][1:-1]
                 if currentUnknownSensor not in unknownSensors.keys():
                    unknownSensors[currentUnknownSensor]=-1  

            else:
                for checkSensor in loadSensorsToMonitor:
                    if ':'+checkSensor+'='  in line and 'threshold' not in line and 'forecast' in checkSensor: #forecast is a global sensor whose value is independent from the host queue status
                       loadSensorsValues[checkSensor]=float(line.split('=')[1])
                    elif ':'+checkSensor+'='  in line and 'threshold' not in line and (queueState == 'n' or queueState == 'd' or queueState == 'o'):  #this condition catches non alarmed 'normal', 'disabled' and 'obsolete' queues
                       loadSensorsValues[checkSensor] = line.split('=')[1]
                    elif ':'+checkSensor+'='  in line and 'threshold' not in line and 'u' in queueState: #this condition only deals with non alarmed u status (u, du)
                       loadSensorsValues[checkSensor]=-1
                                
           
        #adding the information for the current node to the hosts dictionary with the collected load sensors values
        if currentNode!='':

           #managing host queue states
           if currentNode not in hostsQueuesState.keys():
              hostsQueuesState[currentNode]=[]
              hostsQueuesState[currentNode].append(queueState)
           else:
              hostsQueuesState[currentNode].append(queueState)
                                          
           if currentNode not in hosts_dict.keys():
              hosts_dict[currentNode] = dict()
           for currentSensorToCheck in loadSensorsToMonitor: 
               #the current load sensor is in alarm state for the current host
               if currentSensorToCheck in alarmedSensors.keys():
                  hosts_dict[currentNode][currentSensorToCheck] = [alarmedSensors[currentSensorToCheck],'a']         
               #the current load sensor is in unknown state for the current host...
               elif currentSensorToCheck in unknownSensors.keys():
                    #... but not initialized from other queues check
                    if currentSensorToCheck not in hosts_dict[currentNode].keys() or  hosts_dict[currentNode][currentSensorToCheck]==[-255]:
                       hosts_dict[currentNode][currentSensorToCheck] = [unknownSensors[currentSensorToCheck]]
               #the current load sensor is in normal state for the current host...
               elif currentSensorToCheck in loadSensorsValues.keys():
                    if currentSensorToCheck not in hosts_dict[currentNode].keys() or  hosts_dict[currentNode][currentSensorToCheck]==[-255]:
                       hosts_dict[currentNode][currentSensorToCheck] = [loadSensorsValues[currentSensorToCheck]]
               else: #there are no information for the current sensor in current host
                    if currentSensorToCheck not in hosts_dict[currentNode].keys():
                       hosts_dict[currentNode][currentSensorToCheck] = [-255]


    #managing hosts where at least one of the queues is in c/E state
    for host in hostsQueuesState.keys():
        if 'E' in hostsQueuesState[host]:
           for sensor in loadSensorsToMonitor:
               hosts_dict[host][sensor]=[-2]
        elif 'c' in hostsQueuesState[host]:
           for sensor in loadSensorsToMonitor:
               hosts_dict[host][sensor]=[-3]
        elif 'u' in hostsQueuesState[host]: 
            logger.debug('found --- u --- in: %s \n', host)

    logger.debug('queues information: %s\n',pprint.pformat(hostsQueuesState))
   
    logger.debug('Information collected on the nodes through qstat: %s\n',pprint.pformat(hosts_dict))
 
    return hosts_dict    



def parseConf(filename):
    'checks and parses options from the configuration file given as parameter'

    logLevels = {'CRITICAL' : logging.CRITICAL,
                 'ERROR'    : logging.ERROR,
                 'WARNING'  : logging.WARNING,
                 'INFO'     : logging.INFO,
                 'DEBUG'    : logging.DEBUG
                }

    try:
       f = open(filename, 'r')
       jConf=json.loads(f.read())
    except IOError, e:
       print ('Error while accessing the configuration file ' + filename)
       sys.exit (-1)
    except ValueError, e:
       print ('Error while parsing the configuration file: please check its format')
       sys.exit (-1)
    else:
       logger.debug('Configuration file correctly parsed')
    f.close()  
 
    global CONFIG
    CONFIG=dict()
    for optionKey in jConf.keys():
        if 'logfile' in optionKey: 
           logFile=jConf[optionKey]
        elif 'loglevel' in optionKey: 
             if jConf[optionKey] in logLevels.keys():
                logLevel=logLevels[jConf[optionKey]]
             else:
                print ('Please specify a correct logging level in the configuration file')
                sys.exit (-1)
        #elif 'SGEsensors' in optionKey: 
        #     sensors=jConf[optionKey]
        elif 'check_interval' in optionKey:
             checkInterval=jConf[optionKey]
	else:
             CONFIG[optionKey]=jConf[optionKey]

    try:
       #return logFile, logLevel, sensors, int(checkInterval)       
       return logFile, logLevel, int(checkInterval)
 
    except UnboundLocalError, e:
           print ('Error while parsing the configuration file\nSome parameter is missed, please check')
           sys.exit(-1)
    


def checkLoop(doSync, checkTime=120, envFile='/opt/ucl/opsview-gridengine-integration/envFile.json'):
    '''checks SGE load values every checkTime seconds
    nodesSensorsData is a dictionary that will contain all the hosts to be monitored and data collected by the load sensors
    opsviewNodesStatus is a dictionary that will contain all the values to be sent to the Opsview server'''

    if doSync:
              opsviewServer, opsviewHeaders, opener = rest.opsviewAuthentication()
              SGEglobal, SGEHost, OpsHost, hostsgroup = getHostsServicesFromSGEAndOpsview(opsviewServer, opsviewHeaders, opener)

              #syncing hosts between SGE and Opsview
              hostsDiff = compareHosts(SGEHost, OpsHost)

              #adding new SGE hosts into Opsview
              for hostName in hostsDiff['add']:
                  hostIP, hostGroup = getHostInfo(hostName)
                  if hostIP != 'none':
                     rest.checkGroup(opsviewServer, opsviewHeaders, opener, hostGroup)
                     rest.cloneHost(opsviewServer, opsviewHeaders, opener, hostName, hostIP, hostGroup, '1525')

              #deleting from Opsview those nodes no longer defined in SGE
              for hostName in hostsDiff['del']:
                  rest.deleteHost(opsviewServer, opsviewHeaders, opener, hostName)
                  logger.info('I have deleted host %s from Opsview', hostName)

              OPS = getGlobalServicesFromOpsview(opsviewServer, opsviewHeaders, opener)

              try:
                 sensorsInfo = checkSensorsExistance(SGEglobal)
   
              except UnboundLocalError, e:
                  logger.error('One of the requested load sensors does not exist into SGE')     
                  sys.exit(-1)

              syncGlobalServices(SGEglobal, OPS, opsviewServer, opsviewHeaders, opener)
                 
              #updating host dict again to include new sensors added to the template!
              SGEglobal, SGEHost, OpsHost, hostsgroup = getHostsServicesFromSGEAndOpsview(opsviewServer, opsviewHeaders, opener)

              syncHostsServices(SGEHost, OpsHost, opsviewServer, opsviewHeaders, opener, hostsgroup)
              rest.reloadConfiguration(opsviewServer, opsviewHeaders, opener)

              #storing permanently the current environment for next daemon execution without the -s flag
              environment = dict()
              environment['hostsgroup']=hostsgroup
              environment['SGEglobal']=SGEglobal
              environment['SGEHost']=SGEHost      
  
              logger.debug('Environment file is %s', envFile)
              logger.info('Saving to config file: %s', envFile)
 
              f = open(envFile, 'w')
              f.write(json.dumps(environment))
              f.close()

    else:
              #checking if the environment file does exist
              try:
                  f = open(envFile, 'r')
                  environment = json.loads(f.read())
                  f.close()
 
              except IOError, e:
                  logger.fatal('Fatal error %s\nCannot find environment file %s. Run with -s first', e, envFile)
                  sys.exit(-1)

              #loading parameters from the environment file
              hostsgroup = environment['hostsgroup']
              SGEglobal = environment['SGEglobal']
              SGEHost = environment['SGEHost']

              logger.debug('Previously stored load sensor list:\n%s', pprint.pformat(SGEglobal))

              try:
                 sensorsInfo = checkSensorsExistance(SGEglobal)

              except UnboundLocalError, e:
                  logger.error('One of the requested load sensors does not exist into Opsview')
                  sys.exit(-1)
 
    while True:
          try:
             nodesSensorsData = parseHostsState(SGEglobal.keys())
             opsviewNodesStatus = checkNodesState(sensorsInfo,nodesSensorsData,SGEHost)
             generateNSCAMessages(nodesSensorsData,opsviewNodesStatus,hostsgroup)
             logger.debug('Sleeping for %s seconds',checkTime)
             time.sleep(checkTime)

          except UnboundLocalError, e: #new exception types should be created
             logger.error('A problem occurred while checking nodes state %s', e) 
             #logger.error('A problem occurred while checking nodes state')


def getGlobalServicesFromOpsview(opsviewServer, opsviewHeaders, opener):
    opsviewServices = rest.retrieveExistingServices(opsviewServer, opsviewHeaders, opener)
    return opsviewServices



def getHostsServicesFromSGEAndOpsview(opsviewServer, opsviewHeaders, opener):
    '''checks load sensors defined into SGE and compares them with service checks defined into Opsview'''

    hostList = getHostsList()
    group = generateGroups(hostList)

    hostsInfo = dict()
    threadPool = dict()
  
    nagtxtSensors = getNagtxt()

    for currentGroup in group.keys():
        logger.info('Creating thread getSensorsInfo for group %s', currentGroup)
        threadPool[currentGroup] = threading.Thread(target=getSensorsInfo, args=(group[currentGroup],hostsInfo,nagtxtSensors))

    opsviewHostsDict = dict()

    tOps = threading.Thread(target=rest.retrieveHostsServices, args=(opsviewHostsDict, opsviewServer, opsviewHeaders, opener))

    for currentGroup in group.keys():
        threadPool[currentGroup].start()

    tOps.start()

    logger.info("Waiting for SGE threads....")
    for currentGroup in group.keys():
        threadPool[currentGroup].join()

    logger.info("Waiting for Opsview thread....")
    tOps.join()

    for host in opsviewHostsDict.keys():
	if re.match(r"^node-[a-z][0-9][0-9][a-z]-[0-9][0-9][0-9]", host):
		logger.info('Matched Opsview host: %s',host)
	else:
		logger.info('Ignoring unmatched Opsview host: %s',host)
		del opsviewHostsDict[host]

    logger.debug('Collected information from SGE for each host:\n %s', pprint.pformat(hostsInfo))
  
    globalSensorsList = generateGlobalSensorsList(hostsInfo)
    logger.debug('Collected information from SGE regarding all the defined load sensors:\n %s', pprint.pformat(globalSensorsList))

    logger.debug('Collected information from Opsview on sensors:\n %s', pprint.pformat(opsviewHostsDict))
   
    return globalSensorsList, hostsInfo, opsviewHostsDict, group



def syncHostsServices(SGEHostsServices, opsviewHostsServices, opsviewServer, opsviewHeaders, opener, hostsgroup):

    logger.info('Synchronizing services between SGE and Opsview for each host')
    
    #deleting opsview services from hosts where the associated load sensors do not exist
    for host in SGEHostsServices.keys():
        if host in opsviewHostsServices.keys():
           existingServices = []          
           if len(opsviewHostsServices[host]['servicechecks']) > 0:
              for service in opsviewHostsServices[host]['servicechecks']:
                  if service['name'] in SGEHostsServices[host]:
                     existingServices.append(service)
              opsviewHostsServices[host]['servicechecks'] = existingServices

    #adding to Opsview those services that are defined in SGE but are not in Opsview already
    for host in SGEHostsServices.keys():
        if host in opsviewHostsServices.keys():
           servicelist = []
           for service in opsviewHostsServices[host]['servicechecks']:
               logger.info('Service %s exists in opsview',service['name'])
               servicelist.append(service['name'])

           for sensor in SGEHostsServices[host].keys():
               service=dict()
               if sensor not in servicelist:
                  logger.info('Sensor %s on host %s is not defined as Opsview Service', sensor, host)
                  service['name']=sensor
                  service['ref']=''
                  opsviewHostsServices[host]['servicechecks'].append(service)
             

    #single thread update
    opsviewDict = dict()
    opsviewDict['list'] = []

    for host in opsviewHostsServices.keys():
        opsviewDict['list'].append(opsviewHostsServices[host])
    
    rest.modifyHostsServices(opsviewDict, opsviewServer, opsviewHeaders, opener)
    logger.info('All hosts services have been synchronized between SGE and Opsview')


'''    
    #updating the hosts: splitting them on different json objects before updating Opsview through different parallel threads. 
    #It isn't working on the current deployment due to mysql issues while trying to update using different threads

    #converting back to an opsview suitable format
    opsviewDict = dict()
 
    
    for group in hostsgroup.keys():
        opsviewDict[group] = dict()
        opsviewDict[group]['list'] = []

        for host in hostsgroup[group].split():
            if host in opsviewHostsServices.keys(): opsviewDict[group]['list'].append(opsviewHostsServices[host])
 
    threadPool = dict()

    for currentGroup in hostsgroup.keys():
        logger.info('Creating thread for modifying host services on group %s', currentGroup)
        threadPool[currentGroup] = threading.Thread(target=rest.modifyHostsServices, args=(opsviewDict[currentGroup], opsviewServer, opsviewHeaders, opener))

    for currentGroup in hostsgroup.keys():
        threadPool[currentGroup].start()

    for currentGroup in hostsgroup.keys():
        threadPool[currentGroup].join()

    logger.info('All hosts services have been synchronized between SGE and Opsview')
'''


def syncGlobalServices(SGEServices, opsviewServices, opsviewServer, opsviewHeaders, opener):

    logger.info('Synchronizing services between SGE and Opsview')

    logger.info('Current Opsview services: %s', opsviewServices)
    logger.info('Current SGE services: %s', SGEServices.keys())
	

    if len(SGEServices) < 1: 
       logger.error('No services coming from SGE!')
       sys.exit(-1)
    else:
       for service in SGEServices.keys():
           if service not in opsviewServices:
              logger.info('service %s exists into SGE and does not into Opsview', service)
              rest.cloneService(opsviewServer, opsviewHeaders, opener, service)
        
       for service in opsviewServices:
           if service not in SGEServices:
              logger.info('service %s exists into Opsview and does not into SGE (but who cares? not deleting', service)
              #rest.deleteService(opsviewServer, opsviewHeaders, opener, service)



def main(argv):
    #parsing input parameters
    runForeground=False #assuming default behaviour as daemon
    doSync=False

    try:
        opts, args = getopt.getopt(argv[1:],'sfhc:',['sync','foreground','help','config='])
    except getopt.GetoptError, err:
        print '%s\n%s: %s' % (err, 'please use',argv[0] + ' [-h | --help] -c <confFile> | --config=<confFile> [-f | --foreground] [-s | --sync]')
        sys.exit(-2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
           print '%s: %s' % ('Use',argv[0] + ' [-h | --help] -c <confFile> | --config=<confFile> [-f | --foreground] [-s | --sync]')
           sys.exit(0)
        elif opt in ("-c", "--config"):
           confFile = arg
        elif opt in ("-f", "--foreground"):
           runForeground=True
        elif opt in ("-s", "--sync"):
           doSync=True

    #parsing the configuration file and getting related values
    try:
       globalLogFile,globalLogLevel,checkInterval=parseConf(confFile)

    except UnboundLocalError, e:
       print '%s\n%s: %s' % ('Please specify the configuration file', 'Use', argv[0] + ' [-h | --help] -c <confFile> | --config=<confFile> [-f | --foreground] [-s | --sync]')
       sys.exit(-1)

    logger.setLevel(globalLogLevel)
    frmt = logging.Formatter('%(module)s - %(asctime)s - %(levelname)s: %(message)s')

    if not runForeground:
       fh = logging.FileHandler(globalLogFile)
    else:
       fh = logging.StreamHandler()

    fh.setFormatter(frmt)
    logger.addHandler(fh)

    #setting logger configuration for the rest API module as well 
    fileToPreserve = rest.SetLogger(globalLogFile, globalLogLevel, runForeground)

    if not runForeground:  
       context = daemon.DaemonContext()
       context.files_preserve = [fh.stream, fileToPreserve.stream]
       context.open()
    
       try:
          checkLoop(doSync, checkInterval)   
       finally:
          context.close() 
   
    else:
       checkLoop(doSync, checkInterval)



if  __name__ =='__main__':
    logger = logging.getLogger('SGEOpsview')
    main(sys.argv)


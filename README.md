opsview-gridengine-integration
==============================

This project has been created with the aim of monitoring Legion nodes status through Opsview. 

A python daemon periodically parses load sensors values made available from SGE, and injects them into the Opsview monitoring server through NSCA.

As prerequisite, on the machine where the service will run the following packages have to installed:

* python-daemon
* python-simplejson

The sgeopsview init.d script located in the repository supports the standard linux service options (_start_, _stop_, _status_ and _restart_) and adds _sync_ as additional feature (we will further explain it in the following).

The daemon essentially consists of two different python modules: SGEOpsview.py and OpsviewREST.py.

* *SGEOpsview.py* is the main module, implementing the daemon logic and data parsing/formatting features.
* *OpsviewREST.py* is a python wrapper to the Opsview RESTful API, and makes available some useful functions to interact with the Opsview server in a batch fashion.

If you wish to start the daemon not as a system service, you can launch it from the command line as follows:

{code}
[cceaftu@nfs-1 SGEdaemon]$ ./SGEOpsview.py
Please specify the configuration file
Use: ./SGEOpsview.py [-h | --help] -c <confFile> | --config=<confFile> [-f | --foreground] [-s | --sync]
{code}

As the above output states, when launching the daemon, it is mandatory to specify the configuration file path to which refer, otherwise the program will refuse to start. The configuration file consists of three entries formatted according to the JSON format:

{code}
[cceaftu@nfs-1 SGEdaemon]$ cat conf.json
{
 "logfile"        : "/usr/local/nagios/libexec/SGEdaemon/SGEOpsview.log",
 "loglevel"       : "INFO",
 "check_interval" : "120"
}
{code}

* *"logfile"* element contains the path of the file on which messages coming from the daemon will be logged when it will be started in background mode (this is the default mode).
* *"loglevel"* element contains the verbosity level that will be used for the logger (from lowest to highest: CRITICAL, ERROR, WARNING, INFO and DEBUG).
* *"check_interval"* is a value (in seconds) stating how often the daemon will contact the SGE master for retrieving the load sensors values and sending them to Opsview through NSCA.

The other options supported by the daemon are:

* *\[-f \| \--foreground\]* for starting the daemon as a standard console program (foreground). The logging messages will be produced on the console and nothing will be written on the logfile.
* *\[-s \| \--sync\]* for synchronizing the currently defined SGE load sensors with the service checks defined into Opsview for each host, before entering in the data retrieval loop. This process takes a very long time to be carried out although it is implemented using a multi-threaded algorithm (3-4 minutes). It will also restart the Opsview monitoring server for updating its configuration.

The service *sgeopsview* is added within the runlevels 3-4-5 of the nfs-1 machine so it will be started at boot time. Anyway, if any further operation is required, it can be started/stopped using the 'service' Red Hat utility as follows:

{code}
[root@nfs-1 ~]# service sgeopsview start
{code}

{code}
[root@nfs-1 ~]# service sgeopsview stop
{code}

It is possible to see the status of the service as well:
{code}
[root@nfs-1 ~]# service sgeopsview status
{code}

and starting it with the SGE - Opsview sensors/services synchronization before:

{code}
[root@nfs-1 ~]# service sgeopsview sync
{code}

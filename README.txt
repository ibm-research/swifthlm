===============================================
SwiftHLM (Swift Hight-Latency Media) middleware
===============================================

# (C) Copyright 2016 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

### Version: 0.2.1

### Authors:
Slavisa Sarafijanovic (sla@zurich.ibm.com)
Harald Seipp (seipp@de.ibm.com)

### Content:
1. Description (Function Overview)
2. Requirements
3. Install
4. Configure
5. Activate
6. HLM Backend
7. External Interface and Usage Examples 
8. Desing/internals Overview
9. References

1. Description (Function Overview)
===============================================

SwiftHLM is useful for running OpenStack Swift on top of high
latency media (HLM) storage, such as tape or optical disk archive based
backends, allowing to store cheaply and access efficiently large amounts of
infrequently used object data.

SwiftHLM can be added to OpenStack Swift (without modifying Swift itself) to
extend Swift's interface and thus allow to explicitly control and query the
state (on disk or on HLM) of Swift objects data, including efficient prefetch
of bulk of objects from HLM to disk when those objects need to be accessed.
This function previously missing in Swift can be seen similar to Amazon Glacier
[1], either through the Glacier API or the Amazon S3 Lifecycle Management API
[2].

BDT Tape Library Connector (open source) [3] and IBM Spectrum Archive [4] are
examples of HLM backends that provide important and complex functions to manage
HLM resources (tape mounts/unmounts to drives, serialization of requests for
tape media and tape drives resources) and can use SwiftHLM functions for a
proper integration with Swift.

Access to data stored on HLM could be done transparently, without using
SwiftHLM, but that does not work well in practice for many important use cases
and for various reasons as discussed in [5]. In [5] it is also explained how
SwiftHLM function can be orthogonal and complementary to Swift (ring to ring)
tiering [6].

SwiftHLM version 0.2.1 provides the following basic HLM functions on the external
Swift interface:

- MIGRATE (container or an object from disk to HLM)
- RECALL (i.e. prefetch a container or an object from HLM to disk)
- STATUS (get status for a container or an object)
- REQUESTS (get status of migration and recall requests previously submitted
  for a contaner or an object).

MIGRATE and RECALL are asynchronous operations, meaning that the request from
user is queued and user's call is responded immediately, then the request is
processed as a background task. Requests are currently processed in a FIFO
manner (scheduling optimizations are future work).  REQUESTS and STATUS are
synchronous operations that block the user's call until the queried information
is collected and returned.

Detailed (still exemplary and not standardized) syntax and usage examples are 
provided below in section "7. External Interface and Usage Examples".

For each of these functions, SwiftHLM Middleware invokes additional SwiftHLM
components to perform the task, which includes calls to HLM storage backend,
for which a generic backend interface is defined below in section "6. HLM
Backend". Description of other components is provided in the header of
the implementation file for each component. 

2. Requirements
=============================================== 

- OpenStack Swift Juno, Kilo, or Liberty (tested) or a later release (not
  tested)
- HLM backend that supports SwiftHLM functions, see HLM Backend section below
  for details
- Python 2.7+


3. Install
===============================================

    Unpack swifthlm.tgz into /opt/swifthlm
    Alternatively get it from https://github.com/ibm-research/swifthlm, and
    store into /opt/swifthlm

    Then:
    # cd /opt/swifthlm
    # python setup.py install


4. Configure
===============================================

4.1. Configure SwiftHLM middleware to work with Swift

  a) If Swift is installed from source
    Modify Swift's configuration file /etc/swift/proxy-server.conf to include hlm middleware.
    In section [pipeline:main] add hlm keyword into pipeline, e.g.:

      pipeline = catch_errors gatekeeper healthcheck proxy-logging cache bulk tempurl formpost slo dlo ratelimit tempauth hlm staticweb container-quotas account-quotas proxy-logging proxy-server

    Add a new section:
      # High latency media (hlm) middleware
      [filter:hlm]
      use = egg:swifthlm#swifthlm

  b) If Swift installed as part of Spectrum Scale 4.2.1 and later:

    # mmces service stop OBJ --all

    Retrieve your current Swift middleware pipeline setting:
    # mmobj config list --ccrfile proxy-server.conf --section pipeline:main --property pipeline

    Example output for the previous command:
    pipeline = healthcheck cache formpost tempurl swift3 s3token authtoken keystoneauth container-quotas account-quotas staticweb bulk slo dlo proxy-server

    Create a file called
    /tmp/proxy-server.conf.merge
    and fill it with the following contents, re-using the pipeline= line from the
    previous command output with hlm added before proxy-server:
    [pipeline:main]
    pipeline =  healthcheck cache formpost tempurl swift3 s3token authtoken keystoneauth container-quotas account-quotas staticweb bulk slo dlo hlm proxy-server

      [filter:hlm]
      use = egg:swifthlm#swifthlm

      To write back the configuration and register the swifthlm middleware, run:
      # mmobj config change --ccrfile proxy-server.conf --merge-file /tmp/proxy-server.conf.merge

4.2 Configure swift user passwordless ssh between the Swift nodes. Swift user
is not a privileged user and cannot execute privileged operations.

Steps:
- use ssh-keygen to generate RSA keys on Dispatcher node
- cp content of /home/swift/.ssh/id_rsa.pub from Dispatcher node into
  /home/swift/.ssh/authorized_keys on storage nodes 

4.3 Configure SwiftHLM to use a specific connector/backend, as instructed in
Section 6. HLM Backend. If SwiftHLM is not configured to use a specific
connector/backend, a dummy connector/backend provided and installed as part of
SwiftHLM will be used as the default one.

5. Activate
===============================================

To activate the middleware, restart Swift services:

  a) Swift installed from source:
    # swift-init main reload

  b) Spectrum Scale 4.1.1 or later:
    # mmces service start OBJ --all

Note: Before SwiftHLM can be used (Section 7), an HLM Backend needs to be
installed and configured (Section 6).

To start SwiftHLM Dispatcher service (one one node, e.g. a proxy node):
    # python -m swifthlm.dispatcher &
    # to stop it:
    # kill $(pgrep -f 'python -m swifthlm.dispatcher')
    # TODO: look for a better way run the dispatcher background process

6. HLM Backend
===============================================

An HLM backend that supports SwiftHLM functions (MIGRATE, RECALL, STATUS) is
exposed to Swift in the same way as if SwiftHLM is not used (via a file system
interface and a Swift ring definition), plus it needs to additionally support
processing and responding requests from SwiftHLM middleware for performing
SwiftHLM functions.

SwiftHLM Handler is the component of SwiftHLM  that invokes backend HLM
operations via SwiftHLM generic backend interface (GBI). For each backend a
Connector needs to be implemented that maps GBI requests to the backend HLM
operations. 

A backend specific connector can be installed as a standard python module, or
simply stored as a .py file at arbirary location to which the swift user has
access. Then SwiftHLM should be configured to use that specific
connector/backend, by appending the content of
swifthlm/object-server.conf.merge file to /etc/swift/object-server.conf, and
edditing the corresponding configuration values to match the specific
connector/backend. 

Example of the content of edited swifthlm/object-server.conf.merge, to use it
with IBM Spectrum Archive storage backend (assuming the corresponding connector
is available and installed - DISCLAIMER: availability or not availability of
such a connector for IBM Spectrum Archive is not stated or implied by this
configuration example) is:

### High latency media (hlm) configuration on storage node
[hlm]
## You can override the default log level here:
# set log_level = INFO
set log_level = DEBUG
## Backend connector that will be used is defined here
# Dummy Connector/Backend - used by default if no connector is defined
#backend_connector_module = swifthlm.dummy_connector
# IBM Connector
# Define EITHER connector_module:
backend_connector_module = swifthlmibmsa.ibmsa_swifthlm_connector
# OR connector_dir and connector_filename:
#backend_connector_dir = /opt/ibm/ibmsa-swifthlm-connector/swifthlmibmsa
#backend_connector_filename = ibmsa_swifthlm_connector.py
## Location for temporary swifthlm files
# Dummy Connector/Backend
#swifthlm_tmp_dir = /tmp/swifthlm
# IBM Connector/Backend
swifthlm_tmp_dir = /ibm/gpfs/tmp/swifthlm


7. External Interface and Usage Examples 
===============================================


* Syntax for using SwiftHLM enabled Swift via a standard (unmodified) curl Swift client:

curl -H "X-Auth-Token: $TOKEN" -X POST "http://zagreb.zurich.ibm.com:8080/hlm/v1/migrate/AUTH_test/cont1
curl -H "X-Auth-Token: $TOKEN" -X POST "http://zagreb.zurich.ibm.com:8080/hlm/v1/recall/AUTH_test/cont1
curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb.zurich.ibm.com:8080/hlm/v1/status/AUTH_test/cont1
curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb.zurich.ibm.com:8080/hlm/v1/requests/AUTH_test/cont1


* Examples of outputs for the above commands:

##### Get status of Object cont3/obj00:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/status/AUTH_test/cont3/obj00" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    38  100    38    0     0     46      0 --:--:-- --:--:-- --:--:--    46
{
    "/AUTH_test/cont3/obj00": "resident"
}

real    0m0.831s
user    0m0.017s
sys     0m0.008s
[root@belgrade ~]#

##### Get status of all Objects of Container cont3:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/status/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   114  100   114    0     0    128      0 --:--:-- --:--:-- --:--:--   128
{
    "/AUTH_test/cont3/obj00": "resident",
    "/AUTH_test/cont3/obj01": "resident",
    "/AUTH_test/cont3/obj02": "resident"
}

real    0m0.892s
user    0m0.016s
sys     0m0.007s
[root@belgrade ~]#

##### Migrate Object cont3/obj00:

[root@belgrade ~]#
[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X POST "http://zagreb:8080/hlm/v1/migrate/AUTH_test/cont3/obj00"
Accepted migrate request.

real    0m0.058s
user    0m0.001s
sys     0m0.003s
[root@belgrade ~]#

##### Check if request to migrate Object cont3/obj00 is completed:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/requests/AUTH_test/cont3/obj00" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    68  100    68    0     0   1910      0 --:--:-- --:--:-- --:--:--  1942
[
    "20170303034043.566--migrate--AUTH_test--cont3--0--obj00--pending"
]

real    0m0.041s
user    0m0.017s
sys     0m0.007s
[root@belgrade ~]#

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/requests/AUTH_test/cont3/obj00" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    53  100    53    0     0   1566      0 --:--:-- --:--:-- --:--:--  1606
[
    "There are no pending or failed SwiftHLM requests."
]

real    0m0.039s
user    0m0.013s
sys     0m0.010s
[root@belgrade ~]#

##### Get status of all Objects of Container cont3:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/status/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   114  100   114    0     0    115      0 --:--:-- --:--:-- --:--:--   115
{
    "/AUTH_test/cont3/obj00": "migrated",
    "/AUTH_test/cont3/obj01": "resident",
    "/AUTH_test/cont3/obj02": "resident"
}

real    0m0.991s
user    0m0.013s
sys     0m0.010s
[root@belgrade ~]#

##### Migrate entire container cont3 (but make tape backend unavailable on one of the storage nodes):

ot@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X POST "http://zagreb:8080/hlm/v1/migrate/AUTH_test/cont3"
Accepted migrate request.

real    0m0.062s
user    0m0.003s
sys     0m0.003s
[root@belgrade ~]#

##### Check requests for Container cont3:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/requests/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    61  100    61    0     0   1923      0 --:--:-- --:--:-- --:--:--  1967
[
    "20170303034800.465--migrate--AUTH_test--cont3--0--pending"
]

real    0m0.039s
user    0m0.015s
sys     0m0.007s
[root@belgrade ~]#

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/requests/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    60  100    60    0     0   1673      0 --:--:-- --:--:-- --:--:--  1714
[
    "20170303034800.465--migrate--AUTH_test--cont3--0--failed"
]

real    0m0.041s
user    0m0.015s
sys     0m0.008s
[root@belgrade ~]#

##### Get status of all Objects of Container cont3 (tape backend is fixed and again available):

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/status/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   113  100   113    0     0    103      0  0:00:01  0:00:01 --:--:--   103
{
    "/AUTH_test/cont3/obj00": "migrated",
    "/AUTH_test/cont3/obj01": "unknown",
    "/AUTH_test/cont3/obj02": "migrated"
}

real    0m1.103s
user    0m0.014s
sys     0m0.009s
[root@belgrade ~]#

##### Resubmit migration for Container cont3:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X POST "http://zagreb:8080/hlm/v1/migrate/AUTH_test/cont3"
Accepted migrate request.

real    0m0.057s
user    0m0.000s
sys     0m0.004s
[root@belgrade ~]#
[root@belgrade ~]#
[root@belgrade ~]#

##### Check requests for Container cont3:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/requests/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   121  100   121    0     0   3275      0 --:--:-- --:--:-- --:--:--  3361
[
    "20170303035302.857--migrate--AUTH_test--cont3--0--pending",
    "20170303034800.465--migrate--AUTH_test--cont3--0--failed"
]

real    0m0.043s
user    0m0.015s
sys     0m0.009s
[root@belgrade ~]#

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/requests/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    53  100    53    0     0   1780      0 --:--:-- --:--:-- --:--:--  1827
[
    "There are no pending or failed SwiftHLM requests."
]

real    0m0.035s
user    0m0.011s
sys     0m0.012s
[root@belgrade ~]#

##### Get status of Objects of Container cont3:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/status/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   114  100   114    0     0    104      0  0:00:01  0:00:01 --:--:--   105
{
    "/AUTH_test/cont3/obj00": "migrated",
    "/AUTH_test/cont3/obj01": "migrated",
    "/AUTH_test/cont3/obj02": "migrated"
}

real    0m1.092s
user    0m0.017s
sys     0m0.006s
[root@belgrade ~]#

##### Recall all Objects of Container cont3:

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X POST "http://zagreb:8080/hlm/v1/recall/AUTH_test/cont3"
Accepted recall request.

real    0m0.064s
user    0m0.000s
sys     0m0.005s
[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/requests/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    53  100    53    0     0   1821      0 --:--:-- --:--:-- --:--:--  1827
[
    "There are no pending or failed SwiftHLM requests."
]

real    0m0.035s
user    0m0.011s
sys     0m0.012s
[root@belgrade ~]#

##### Get status of Objects of Container cont3 (now on disk and tape, thus "premigrated"):

[root@belgrade ~]# time curl -H "X-Auth-Token: $TOKEN" -X GET "http://zagreb:8080/hlm/v1/status/AUTH_test/cont3" | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   123  100   123    0     0    125      0 --:--:-- --:--:-- --:--:--   125
{
    "/AUTH_test/cont3/obj00": "premigrated",
    "/AUTH_test/cont3/obj01": "premigrated",
    "/AUTH_test/cont3/obj02": "premigrated"
}

real    0m0.986s
user    0m0.015s
sys     0m0.007s
[root@belgrade ~]#

##### 


8. Design/Internals Overview

This section provides overview of SwiftHLM components and their join operation
for providing the function described in section 1.

SwiftHLM workflow for processing MIGRATION requests (and it is same for RECALL
requests) is as follows.  SwiftHLM middleware on proxy server intrcepts
SwiftHLM migration requests and queues them inside Swift, by storing them into
a special HLM-dedicated container as zero size objects.  After SwiftHLM request
is queued, 202 code is returned to the application.

Another SwiftHLM process, called SwiftHLM Dispatcher, is processing the queued
requests asynchronously with respect to user/application that submitted them.
It picks a request from the queue, in FIFO or a more advance manner, and groups
the requests into one list per involved storage node. 

For each storage node/list Dispatcher invokes remotely a SwiftHLM program on
that storage node (the name of that program is SwiftHLM Handler), and provides
it with the list. Handler could also be a long running process listening for
and processing submissions from Dispatcher. Either way, the function performed
by Handler is to map the objects to files (or to HLM backend objects) and
submits the file list and the migration requests to HLM backend, if the backend
already provide the function to move data between LLM (low latency media) and
HLM (hight latency media). Examples of backends with such function are IBM
Spectrum Archive and BDT Tape Library Connector. 

In order to support different backends, a Generic Backend Interface is defined
and used by Handler to submit the request to HLM backend, via the backend
specific Connector that maps the request to the backend specific API. If HLM
backend does not support moving data and managing object state, the backend
Connector needs to implement that function as well.

Once the backend completes the operation the result (succes or failure) is
propagated back to the dispatcher. In case of success, the request is removed
from the queue, otherwise it is marked as failed and kept in the queue for some
period (to be able to answer the request status queries). One could also
consider implementing request retries. 

Querying object status (STATUS) is processed by SwiftHLM middleware
synchrounously, by groupping the queries per storage nodes and invoking the
Handler (same as Dispatcher does for migration and recall), but for status the
SwiftHLM middleware also merges the statuses reportd by the backend and
provides the merged result to the Swift application.

Querying requests status (REQUESTS) Query for requests status for an object or
a container are processed by SwiftHLM middleware, by reading listing of the
special HLM-dedicated container(s). If there are not pending (incompleted or
failed) requests for a container, the previously submitted operations for that
container may be considered completed. This is more efficient than to query
state for each object of a container.

9. References
===============================================
[1] Amazon Glacier API, http://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-api.html  
[2] Amazon S3 integration with Glacier, https://aws.amazon.com/blogs/aws/archive-s3-to-glacier   
[3] Tape Library Connector, https://github.com/BDT-GER/SWIFT-TLC
[4] IBM Spectrum Archive, http://www-03.ibm.com/systems/storage/tape/ltfs/
[5] SwiftHLM design discussion,  https://wiki.openstack.org/wiki/Swift/HighLatencyMedia
[6] Swift ring to ring tiering, https://review.openstack.org/#/c/151335/3/specs/in_progress/tiering.rst

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

### Version: 0.1

### Authors:
Slavisa Sarafijanovic (sla@zurich.ibm.com)
Harald Seipp (seipp@de.ibm.com)

### Content:
1. Description
2. Requirements
3. Install
4. Configure
5. Activate
6. HLM Backend
7. External Interface and Usage Examples 
8. References

1. Description
===============================================

SwiftHLM middleware is useful for running OpenStack Swift on top of high
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

SwiftHLM version 0.1 provides the following basic HLM functions on the external
Swift interface:
- MIGRATE (container or an object from disk to HLM)
- RECALL (i.e. prefetch a container or an object from HLM to disk) 
- STATUS (get status for an object or a container objects).

Detailed (still exemplary and not standardized) syntax and usage examples are 
provided below in section "External Interface and Usage Examples".


2. Requirements
=============================================== 

- OpenStack Swift Juno (tested) or Kilo (tested) or a later release (not
  tested)
- HLM backend that supports SwiftHLM functions, see HLM Backend section below
  for details
- Python 2.7+


3. Install
===============================================

    # python setup.py install


4. Configure
===============================================

  a) If Swift is installed from source
    Modify Swift's configuration file /etc/swift/proxy-server.conf to include hlm middleware.
    In section [pipeline:main] add hlm keyword into pipeline, e.g.:

      pipeline = catch_errors gatekeeper healthcheck proxy-logging cache bulk tempurl formpost slo dlo ratelimit tempauth hlm staticweb container-quotas account-quotas proxy-logging proxy-server

    Add a new section:
      # High latency media (hlm) middleware
      [filter:hlm]
      use = egg:swifthlm#swifthlm

  b) If Swift installed as part of Spectrum Scale 4.1.1 and later:

    # mmces service stop OBJ --all

    Retrieve your current Swift middleware pipeline setting:
    # mmobj config list --ccrfile proxy-server.conf --section pipeline:main --property pipeline

    Example output for the previous command:
    pipeline = healthcheck cache formpost tempurl swift3 s3token authtoken keystoneauth container-quotas account-quotas staticweb bulk slo dlo hlm proxy-server

    Insert hlm before proxy-server and write back the configuration - for the above example:
    # mmobj config change --ccrfile proxy-server.conf --section pipeline:main --property pipeline --value "healthcheck cache formpost tempurl swift3 s3token authtoken keystoneauth container-quotas account-quotas staticweb bulk slo dlo hlm proxy-server"

    Register the swifthlm middleware:
    # mmobj config change --ccrfile proxy-server.conf --section filter:hlm --property use --value egg:swifthlm#swifthlm

5. Activate
===============================================

To activate the middleware, restart Swift services:


  a) Swift installed from source:
    # swift-init main reload

  b) Spectrum Scale 4.1.1 or later:
    # mmces service start OBJ --all


6. HLM Backend
===============================================

An HLM backend that supports SwiftHLM functions (MIGRATE, RECALL, STATUS) is
exposed to Swift in the same way as if SwiftHLM is not used (via a file system
interface and a Swift ring definition), plus it needs to additionally support
processing and responding requests from SwiftHLM middleware for performing
SwiftHLM functions.

This additional SwiftHLM middleware to HLM backend interface is aimed to be
configurable and a particular HLM backend needs to support at least one of the
two options:
a) The backend accepts and responds requests from SwiftHLM via a CLI interface
b) SwiftHLM communicates to the backend via a pair of object extended
attributes, the requested state (RS) set by SwiftHLM and read by the backend,
and the current state (CS) set by the backend and read by the SwiftHLM. E.g. if
a Swift application requests migrating a container to HLM, SwiftHLM middleware
identifies the involved objects and updates RS for each, and the backend either
intercepts or scans RS updates, performs data migration, and updates CS.

Depending on the implementation feasibility and desired processing efficiency,
different HLM backends may prefer one option over the other.

Importantly, whatever option is configured and used SwiftHLM exposes the same
external interface to the applications.

Current SwiftHLM (Version 0.1) only supports option a, and this option by
default assumes the backend executables for supporting SwiftHLM operations are
stored (installed) as:
/opt/ibm/swift-hlm-backend/migrate
/opt/ibm/swift-hlm-backend/recall
/opt/ibm/swift-hlm-backend/status

for the MIGRATE, RECALL, and STATUS function respectively.

If your backend executables to support SwiftHLM need to be installed to a
different location or named differently, e.g.: 

/install/swift-backend/swift-hlm-cli/mig
/install/swift-backend/swift-hlm-cli/rec
/install/swift-backend/swift-hlm-cli/status

... then configure that in /etc/proxy-server.conf under [filter:hlm] section,
for the above example the configuration entries would be as follows: 

# High latency media (hlm) middleware
[filter:hlm]
use = egg:swift#hlm
migrate_backend = /install/swift-backend/swift-hlm-cli/mig
recall_backend = /install/swift-backend/swift-hlm-cli/rec
status_backend = /install/swift-backend/swift-hlm-cli/status

The inputs/output for the executables are:
* migrate, recall: 
in: path, requestId
out: accept_request_return_code
* status:
in: path, requestId
out: status result, one line per object

... where:
'path' is a container or an object path written as account/container, e.g.
test/cont1, or as account/container/object, e.g. test/cont1/obj0,
'requestId' is a 12 bits long integer (aimed for referring related request, so
far randomly generated by SwiftHLM and not used),
'accept_request_return_code' is 0 if request is accepted, else another value, 
'status result' is multiple lines of standard output, one per involved object
reporting the status of the object in the following format (format is not yet
standardized, it might be useful to standardize it):  each containing one line
per involved object.

The above syntax is still exemplary. The interface between SwiftHLM and HLM
backends in not yet fixed or standardized, which would be useful to do in order
to ensure wide SwiftHLM acceptance and backend compatibility.


7. External Interface and Usage Examples 
===============================================

The external Swift interface (SwitHLM extension of it) syntax is still exemplary
and not standardized.

* Syntax for using SwiftHLM enabled Swift via a standard (unmodified) curl Swift client:

# curl -v -H 'X-Storage-Token: AUTH_tk2c0714aa645d40268a753293c678062f' -X GET http://zagreb.zurich.ibm.com:8080/v1/AUTH_test/contT1?STATUS
# curl -v -H 'X-Storage-Token: AUTH_tk2c0714aa645d40268a753293c678062f' -X POST http://zagreb.zurich.ibm.com:8080/v1/AUTH_test/contT1/obj0?MIGRATE
# curl -v -H 'X-Storage-Token: AUTH_tk2c0714aa645d40268a753293c678062f' -X POST http://zagreb.zurich.ibm.com:8080/v1/AUTH_test/contT1/obj0?RECALL

* Examples of outputs for the above commands:

###### Get status of all objects within container contT1:

[root@zagreb objects]# curl -v -H 'X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf' -X GET http://127.0.0.1:8080/v1/AUTH_test/contT1?STATUS
* About to connect() to 127.0.0.1 port 8080 (#0)
*   Trying 127.0.0.1... connected
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /v1/AUTH_test/contT1?STATUS HTTP/1.1
> User-Agent: curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.18 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2
> Host: 127.0.0.1:8080
> Accept: */*
> X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf
>
< HTTP/1.1 200 OK
< Content-Length: 918
< Content-Type: text/plain
< X-Trans-Id: txc1eba7ae46884ed8a8b12-0056967686
< Date: Wed, 13 Jan 2016 16:08:40 GMT
<
Object                        Status      File                                                                                      Tape
/AUTH_test/contT1/obj4        migrated    /srv/node/gpfs/objects-1/793/c83/1ff7a53aa6761f86cb78a16d7cca1c83/1434101306.98312.data   B00030L6
/AUTH_test/contT1/obj3        migrated    /srv/node/gpfs/objects-1/793/1e6/738bfb424ee92f77a46a425f31d031e6/1434101306.98268.data   B00030L6
/AUTH_test/contT1/obj2        migrated    /srv/node/gpfs/objects-1/793/188/7a48e033bb9cd35c7c0c7e87c7e1b188/1437749052.56079.data   B00030L6
/AUTH_test/contT1/obj1        migrated    /srv/node/gpfs/objects-1/793/ef2/cf734da8ff85334ed4b526e0226e6ef2/1438000722.65429.data   B00030L6
/AUTH_test/contT1/obj0        resident    /srv/node/gpfs/objects-1/793/aac/006e3939ccbd5d8801bcfaa318941aac/1452701309.62247.data   -
* Connection #0 to host 127.0.0.1 left intact
* Closing connection #0

###### Get status of single object obj0 within container contT1:

[root@zagreb objects]# curl -v -H 'X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf' -X GET http://127.0.0.1:8080/v1/AUTH_test/contT1/obj0?STATUS
* About to connect() to 127.0.0.1 port 8080 (#0)
*   Trying 127.0.0.1... connected
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /v1/AUTH_test/contT1/obj0?STATUS HTTP/1.1
> User-Agent: curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.18 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2
> Host: 127.0.0.1:8080
> Accept: */*
> X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf
>
< HTTP/1.1 200 OK
< Content-Length: 306
< Content-Type: text/plain
< X-Trans-Id: tx1a280a87c49c4cbf80bec-00569676c8
< Date: Wed, 13 Jan 2016 16:09:45 GMT
<
Object                        Status      File                                                                                      Tape
/AUTH_test/contT1/obj0        resident    /srv/node/gpfs/objects-1/793/aac/006e3939ccbd5d8801bcfaa318941aac/1452701309.62247.data   -
* Connection #0 to host 127.0.0.1 left intact
* Closing connection #0

###### Migrate obj0 to Tape:

[root@zagreb objects]# curl -v -H 'X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf' -X POST http://127.0.0.1:8080/v1/AUTH_test/contT1/obj0?MIGRATE
* About to connect() to 127.0.0.1 port 8080 (#0)
*   Trying 127.0.0.1... connected
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> POST /v1/AUTH_test/contT1/obj0?MIGRATE HTTP/1.1
> User-Agent: curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.18 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2
> Host: 127.0.0.1:8080
> Accept: */*
> X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf
>
< HTTP/1.1 200 OK
< Content-Length: 28
< Content-Type: text/plain
< X-Trans-Id: txab9a433ab13c4de9bfdb1-00569676a5
< Date: Wed, 13 Jan 2016 16:09:09 GMT
<
Accepted migration request.
* Connection #0 to host 127.0.0.1 left intact
* Closing connection #0

###### Get status of Object obj0 (now migrated to tape):

[root@zagreb objects]# curl -v -H 'X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf' -X GET http://127.0.0.1:8080/v1/AUTH_test/contT1/obj0?STATUS
* About to connect() to 127.0.0.1 port 8080 (#0)
*   Trying 127.0.0.1... connected
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /v1/AUTH_test/contT1/obj0?STATUS HTTP/1.1
> User-Agent: curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.18 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2
> Host: 127.0.0.1:8080
> Accept: */*
> X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf
>
< HTTP/1.1 200 OK
< Content-Length: 306
< Content-Type: text/plain
< X-Trans-Id: tx74cfa3546e794878afe01-00569676e6
< Date: Wed, 13 Jan 2016 16:10:14 GMT
<
Object                        Status      File                                                                                      Tape
/AUTH_test/contT1/obj0        migrated    /srv/node/gpfs/objects-1/793/aac/006e3939ccbd5d8801bcfaa318941aac/1452701309.62247.data   B00030L6
* Connection #0 to host 127.0.0.1 left intact
* Closing connection #0

###### Get status of all objects within Container contT1:

[root@zagreb objects]# curl -v -H 'X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf' -X GET http://127.0.0.1:8080/v1/AUTH_test/contT1?STATUS
* About to connect() to 127.0.0.1 port 8080 (#0)
*   Trying 127.0.0.1... connected
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /v1/AUTH_test/contT1?STATUS HTTP/1.1
> User-Agent: curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.18 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2
> Host: 127.0.0.1:8080
> Accept: */*
> X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf
>
< HTTP/1.1 200 OK
< Content-Length: 918
< Content-Type: text/plain
< X-Trans-Id: txc80083cb65974a6383b40-0056967704
< Date: Wed, 13 Jan 2016 16:10:46 GMT
<
Object                        Status      File                                                                                      Tape
/AUTH_test/contT1/obj4        migrated    /srv/node/gpfs/objects-1/793/c83/1ff7a53aa6761f86cb78a16d7cca1c83/1434101306.98312.data   B00030L6
/AUTH_test/contT1/obj3        migrated    /srv/node/gpfs/objects-1/793/1e6/738bfb424ee92f77a46a425f31d031e6/1434101306.98268.data   B00030L6
/AUTH_test/contT1/obj2        migrated    /srv/node/gpfs/objects-1/793/188/7a48e033bb9cd35c7c0c7e87c7e1b188/1437749052.56079.data   B00030L6
/AUTH_test/contT1/obj1        migrated    /srv/node/gpfs/objects-1/793/ef2/cf734da8ff85334ed4b526e0226e6ef2/1438000722.65429.data   B00030L6
/AUTH_test/contT1/obj0        migrated    /srv/node/gpfs/objects-1/793/aac/006e3939ccbd5d8801bcfaa318941aac/1452701309.62247.data   B00030L6
* Connection #0 to host 127.0.0.1 left intact
* Closing connection #0

###### Recall all objects of Container contT1 back to disk:

[root@zagreb objects]# curl -v -H 'X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf' -X POST http://127.0.0.1:8080/v1/AUTH_test/contT1?RECALL
* About to connect() to 127.0.0.1 port 8080 (#0)
*   Trying 127.0.0.1... connected
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> POST /v1/AUTH_test/contT1?RECALL HTTP/1.1
> User-Agent: curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.18 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2
> Host: 127.0.0.1:8080
> Accept: */*
> X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf
>
< HTTP/1.1 200 OK
< Content-Length: 25
< Content-Type: text/plain
< X-Trans-Id: tx55328fbc368a40029c2cd-0056967710
< Date: Wed, 13 Jan 2016 16:10:56 GMT
<
Accepted recall request.
* Connection #0 to host 127.0.0.1 left intact
* Closing connection #0

###### Check status for all objects of Container contT1 (now on disk and tape, thus "premigrated"):

[root@zagreb objects]# curl -v -H 'X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf' -X GET http://127.0.0.1:8080/v1/AUTH_test/contT1?STATUS
* About to connect() to 127.0.0.1 port 8080 (#0)
*   Trying 127.0.0.1... connected
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /v1/AUTH_test/contT1?STATUS HTTP/1.1
> User-Agent: curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.18 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2
> Host: 127.0.0.1:8080
> Accept: */*
> X-Storage-Token: AUTH_tk2da86b9403ea42389d34863ccee7ffbf
>
< HTTP/1.1 200 OK
< Content-Length: 918
< Content-Type: text/plain
< X-Trans-Id: tx4195a82165b54a4c89f3c-005696771d
< Date: Wed, 13 Jan 2016 16:11:15 GMT
<
Object                        Status      File                                                                                      Tape
/AUTH_test/contT1/obj4        premigrated /srv/node/gpfs/objects-1/793/c83/1ff7a53aa6761f86cb78a16d7cca1c83/1434101306.98312.data   B00030L6
/AUTH_test/contT1/obj3        premigrated /srv/node/gpfs/objects-1/793/1e6/738bfb424ee92f77a46a425f31d031e6/1434101306.98268.data   B00030L6
/AUTH_test/contT1/obj2        premigrated /srv/node/gpfs/objects-1/793/188/7a48e033bb9cd35c7c0c7e87c7e1b188/1437749052.56079.data   B00030L6
/AUTH_test/contT1/obj1        premigrated /srv/node/gpfs/objects-1/793/ef2/cf734da8ff85334ed4b526e0226e6ef2/1438000722.65429.data   B00030L6
/AUTH_test/contT1/obj0        premigrated /srv/node/gpfs/objects-1/793/aac/006e3939ccbd5d8801bcfaa318941aac/1452701309.62247.data   B00030L6
* Connection #0 to host 127.0.0.1 left intact
* Closing connection #0
[root@zagreb objects]#


8. References
===============================================
[1] Amazon Glacier API, http://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-api.html  
[2] Amazon S3 integration with Glacier, https://aws.amazon.com/blogs/aws/archive-s3-to-glacier   
[3] Tape Library Connector, https://github.com/BDT-GER/SWIFT-TLC
[4] IBM Spectrum Archive, http://www-03.ibm.com/systems/storage/tape/ltfs/
[5] SwiftHLM design discussion,  https://wiki.openstack.org/wiki/Swift/HighLatencyMedia
[6] Swift ring to ring tiering, https://review.openstack.org/#/c/151335/3/specs/in_progress/tiering.rst

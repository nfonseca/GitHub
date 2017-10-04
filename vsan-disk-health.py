#!/bin/python

import json
import subprocess



jsonstring ="""
    {
    "uuid": "52d81502-c7d7-8203-ace8-23326e41c440",
    "owner": "594edb95-f18d-2be8-77a3-00505681203c",
    "health": "Healthy",
    "revision": "0",
    "type": "HEALTH_STATUS",
    "flag": "2",
    "minHostVersion": "3",
    "md5sum": "4fa95634f147df3f3e8bdd2fb934af8b",
    "valueLen": "24",
    "content": {"healthFlags": 0, "timestamp": 198925002538},
    "errorStr": "(null)"
}"""


jsonstring2=subprocess.check_output("/bin/cmmds-tool find -t HEALTH_STATUS -f json | sed 1,3d 2>/dev/null | grep -v ']'| head -n 13", shell=True)


j = json.loads(jsonstring2)

t=json.loads(jsonstring2)
print(j['uuid'],j['content'])


# todo : import output from cmmds to a scring ....


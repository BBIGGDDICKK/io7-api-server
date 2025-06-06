import json
import logging
from models import NewDevice, Device
from dynsec.topicBase import ACLBase
from dynsec.mqtt_conn import mqClient
from environments import Settings

settings = Settings()
logger = logging.getLogger("uvicorn")
logger.setLevel(settings.LOG_LEVEL)

def add_dynsec_device(device: NewDevice):
    acl = ACLBase(device.devId)
    cmd = {
        'commands': [
            {
                'command': 'createRole',
                'rolename': acl.get_id(),
                'acls': [
                        acl.subTopic('cmdTopic'),
                        acl.subTopic('updateTopic'),
                        acl.subTopic('rebootTopic'),
                        acl.subTopic('resetTopic'),
                        acl.subTopic('upgradeTopic'),
                        acl.pubTopic('logTopic'),
                        acl.pubTopic('metaTopic'),
                        acl.pubTopic('evtTopic')
                ]
            }
        ]
    }

    if device.type == 'gateway':
        cmd['commands'][0]['acls'].append(acl.pubTopic('gw_query'))
        cmd['commands'][0]['acls'].append(acl.pubTopic('gw_add'))
        cmd['commands'][0]['acls'].append(acl.subTopic('gw_list'))

    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd));

    if device.type == 'edge':
        cmd = {
            'commands': [
                {
                    'command': 'addClientRole',
                    'username': device.createdBy,       # This is the edge client's gateway
                    'rolename': device.devId
                }
            ]
        }
        logger.info(f'Creating Edge Client "{acl.get_id()}".')
    else:
        cmd = {
            'commands': [
                {
                    'command': 'createClient',
                    'username': acl.get_id(),
                    'password': device.password,
                    'roles': [
                        {
                            'rolename': acl.get_id(),
                            'priority': -1
                        }
                    ]
                }
            ]
        }
        logger.info(f'Creating Client "{acl.get_id()}".')
        
    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd))


def delete_dynsec_device(device: str):
    cmd = {
        'commands': [
            {
                'command': 'deleteClient',
                'username': device
            }
        ]
    }
    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd))
    logger.info(f'Deleting Device "{device}".')

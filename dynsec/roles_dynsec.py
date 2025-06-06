import json
import logging
from dynsec.topicBase import ACLBase
from dynsec.mqtt_conn import mqClient
from environments import Settings

settings = Settings()
logger = logging.getLogger("uvicorn")
logger.setLevel(settings.LOG_LEVEL)

acl = ACLBase('+')

def add_apps_role():
    cmd = {
        'commands': [
            {
                'command': 'createRole',
                'rolename': '$apps',
                'acls': [
                    acl.subTopic('appSubTopic'),
                    acl.pubTopic('appPubTopic')
                ]
            }
        ]
    }

    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd));
    logger.info('Creating App Role $apps.')
    
def add_io7_adm_role():
    cmd = {
        'commands': [
            {
                'command': 'createRole',
                'rolename': '$io7_adm',
                'acls': [
                    acl.subTopic('gw_add'),
                    acl.subTopic('gw_query'),
                    acl.pubTopic('gw_list'),
                    acl.pubTopic('mgmtTopics')
                ]
            }
        ]
    }

    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd));
    logger.info('Creating Gateway Admin Role $io7_adm.')
    
def assign_role(device: str, role: str):
    cmd = {
        "commands": [
            {
                "command": "addClientRole",
                "username": device,
                "rolename": role,
                "priority": -1
            }
        ]
    }
    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd));
    logger.info(f'Assigning Role {role} to device/app {device}.')

def delete_dynsec_role(role: str):
    if role in ['admin', '$apps', '$io7_adm']:
        logger.info(f'Cannot delete system role "{role}".')
        return
    cmd = {
	    'commands': [
	        {
	            'command': 'deleteRole',
	            'rolename': role
	        }
	    ]
    }
    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd))
    logger.info(f'Deleting Role "{role}".')
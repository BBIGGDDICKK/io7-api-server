import json
import logging
from models import NewIOTApp
from dynsec.mqtt_conn import mqClient
from dynsec.topicBase import ACLBase
from environments import Settings

settings = Settings()
logger = logging.getLogger("uvicorn")
logger.setLevel(settings.LOG_LEVEL)

def add_dynsec_app(app: NewIOTApp):
    # TODO: ensure $apps role exists
    rolename = '$apps'
    if app.restricted:
        rolename = f"$apps_{app.appId}"
        acl = ACLBase(rolename)
        cmd = {
            'commands': [
                {
                    'command': 'createRole',
                    'rolename': acl.get_id(),
                    'acls': [ ]
                }
            ]
        }
        mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd));

    cmd = {
        'commands': [
            {
                'command': 'createClient',
                'username': app.appId,
                'password': app.password,
                'roles': [
                    {
                        'rolename': rolename,
                        'priority': -1
                    }
                ]
            }
        ]
    }

    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd))
    logger.info(f'Creating App ID "{app.appId}".')

def delete_dynsec_app(appId: str):
    cmd = {
        'commands': [
            {
                'command': 'deleteClient',
                'username': appId
            }
        ]
    }
    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd))
    logger.info(f'Deleting App ID "{appId}".')

def add_member(appId: str, devId: str, evt: bool, cmd: bool):
    cmd = {
        "commands": [
            {
                "command": "addRoleACL",
                "rolename": f"$apps_{appId}",
                "acltype": "subscribePattern",
                "topic": f"iot3/{devId}/evt/#",
                "priority": -1,
                "allow": evt
            },
            {
                "command": "addRoleACL",
                "rolename": f"$apps_{appId}",
                "acltype": "publishClientSend",
                "topic": f"iot3/{devId}/cmd/#",
                "priority": -1,
                "allow": cmd
            }
        ]
    }
    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd))
    logger.info(f'Adding device({devId}) to App ID "{appId}".')

def remove_member(appId: str, devId: str):
    cmd = {
        "commands": [
            {
                "command": "removeRoleACL",
                "rolename": f"$apps_{appId}",
                "acltype": "subscribePattern",
                "topic": f"iot3/{devId}/evt/#"
            },
            {
                "command": "removeRoleACL",
                "rolename": f"$apps_{appId}",
                "acltype": "publishClientSend",
                "topic": f"iot3/{devId}/cmd/#"
            }
        ]
    }
    mqClient.publish('$CONTROL/dynamic-security/v1', json.dumps(cmd))
    logger.info(f'Removing device({devId}) from App ID "{appId}".')

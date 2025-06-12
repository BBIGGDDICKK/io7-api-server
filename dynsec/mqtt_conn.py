from datetime import datetime
import time
import logging
import threading
import os
import json
import asyncio
import paho.mqtt.client as mqtt
from environments import Settings, Database, dynsec_role_exists, get_dynsec_admin
from models import Device, NewDevice

settings = Settings()
logger = logging.getLogger("uvicorn")
logger.setLevel(settings.LOG_LEVEL)
device_db = Database(Device.Settings.name)

server = settings.MQTT_HOST
port = settings.MQTT_PORT
username = settings.DynSecUser
password = settings.DynSecPass

def mqtt_dynsec_setup():
    if not dynsec_role_exists('$apps'):
        from dynsec.roles_dynsec import add_apps_role
        add_apps_role()
    if not dynsec_role_exists('$io7_adm'):
        from dynsec.roles_dynsec import add_io7_adm_role, assign_role
        admin_id = get_dynsec_admin()
        if admin_id:
            add_io7_adm_role()
            assign_role(admin_id, '$io7_adm')
        else:
            logger.error('No admin user found in dynsec.json')

def on_message(client, userdata, msg):
    # handle edge device registration and listing
    from routes.devices_router import add_device
    logger.debug("MQTT Message Received: " + msg.topic + " : " + str(msg.payload))
    topic = msg.topic.split('/')
    if topic[3] == 'add':
        obj=json.loads(msg.payload)['d']
        edgeDevice = NewDevice(
            devId =obj['devId'],
            password ='',
            createdBy = topic[1], 
            createdDate = datetime.utcnow(),
            type = 'edge'
        )
        asyncio.run(add_device(edgeDevice))
    elif topic[3] == 'query':
        edges = device_db.get(device_db.qry.createdBy == topic[1])
        edges = [edge['devId'] for edge in edges]
        edges.append(topic[1])
        client.publish(f"iot3/{topic[1]}/gateway/list", json.dumps(edges))
        
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("MQTT Connected with RC : " + str(rc))
        mqtt_dynsec_setup()
        client.subscribe('$CONTROL/dynamic-security/v1/response')
        client.subscribe('iot3/+/gateway/add')
        client.subscribe('iot3/+/gateway/query')
    else:
        logger.warning("MQTT Connected with RC : " + str(rc))

mqClient = mqtt.Client(client_id='api-server')
mqClient.username_pw_set(username, password)
if settings.MQTT_SSL_CERT and os.path.exists(settings.MQTT_SSL_CERT):
    import ssl
    mqClient.tls_set(settings.MQTT_SSL_CERT, tls_version=ssl.PROTOCOL_TLSv1_2)
    mqClient.tls_insecure_set(True)

def mqConnSetup():
    logger.info('MQTT Connection Setup')
    try:
        mqClient.connect(server, port, 60)
        mqClient.on_connect = on_connect
        mqClient.on_message = on_message
        mqClient.loop_start()
    except Exception as e:
        logger.error("MQTT Client Error: " + str(e))
        # if mqtt is not ready, retry after 60 seconds
        time.sleep(60)
        mqConnSetup()    

t = threading.Thread(target=mqConnSetup)
t.start()
 
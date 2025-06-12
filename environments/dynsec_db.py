from typing import List

from pydantic import BaseModel
from tinydb.queries import QueryLike
from environments import Settings
from models.devices import Device
import json

settings = Settings()
dynsec_file = settings.DynSecPath

def dynsec_role_exists(roleId: str) -> bool:
    roles = load_dynsec()['roles']
    for role in roles:
        if role['rolename'] == roleId:
            return True
    return False

def get_dynsec_admin() -> str:
    clients = load_dynsec()['clients']
    for client in clients:
        for role in client['roles']:
            if role['rolename'] == 'admin':
                return client['username']
    return None


def load_dynsec():
    with open(dynsec_file, "r") as file:
        dynsec_json = json.load(file)
    return dynsec_json

def get_client(client_id):
    dynsec_json = load_dynsec()
    return next((c for c in dynsec_json.get("clients",[]) if c.get("username") == client_id), None)

def get_role(role_id):
    dynsec_json = load_dynsec()
    return next((r for r in dynsec_json.get("roles",[]) if r.get("rolename") == role_id), None)

def get_client_roleId(clientId: str):
    if c_id := get_client(clientId):
        if role := next((r for r in c_id.get("roles",[])), None):
            return role.get('rolename', None)
    return None

def get_client_role(clientId):
    if role_id := get_client_roleId(clientId):
        return get_role(role_id)
    return None

def get_device(dev_id: str):
    role = get_client_roleId(dev_id)
    if role and role == dev_id:
        return get_client(dev_id)
    return None

def get_appId(app_id):
    if role := get_client_roleId(app_id):
        if role.startswith('$apps'):
            return get_client(app_id)
    return None

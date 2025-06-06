from typing import List
import logging
from fastapi import APIRouter, HTTPException, status, Depends
from datetime import timezone, timedelta
from secutils import authenticate
from environments import Database
from models import Device, NewDevice, IOTApp, FirmwareInfo
from dynsec.devices_dynsec import add_dynsec_device, delete_dynsec_device
from dynsec.roles_dynsec import delete_dynsec_role
from dynsec.devices_actions import reboot_device_action, reset_device_action, update_metadata_action, upgrade_firmware_action
from environments import Settings

settings = Settings()
logger = logging.getLogger("uvicorn")
logger.setLevel(settings.LOG_LEVEL)
kst=timezone(timedelta(hours=9))

device_db = Database(Device.Settings.name)
apps_db = Database(IOTApp.Settings.name)
router = APIRouter(tags=['Devices'])

@router.get('/reboot/{devId}')
async def reboot_device(devId: str, jwt: str = Depends(authenticate)) -> dict:
    device = device_db.getOne(device_db.qry.devId == devId)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device(devId:{devId}) does not exist"
        )
    reboot_device_action(devId)
    return {"message": "Rebooting Device", "devId": devId}

@router.get('/reset/{devId}')
async def reset_device(devId: str, jwt: str = Depends(authenticate)) -> dict:
    device = device_db.getOne(device_db.qry.devId == devId)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device(devId:{devId}) does not exist"
        )
    reset_device_action(devId)
    return {"message": "Factory Resetting Device", "devId": devId}

@router.post('/update/{devId}')
async def update_metadata(devId: str, metaData: dict, jwt: str = Depends(authenticate)) -> dict:
    qryDevice = device_db.getOne(device_db.qry.devId == devId)
    if not qryDevice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device(devId:{devId}) does not exist"
        )
    update_metadata_action(devId, metaData)
    return {"message": "Metadata being updated", "devId": devId}

@router.post('/upgrade/{devId}')
async def upgrade_firmware(devId: str, fwInfo: FirmwareInfo, jwt: str = Depends(authenticate)) -> dict:
    qryDevice = device_db.getOne(device_db.qry.devId == devId)
    if not qryDevice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device(devId:{devId}) does not exist"
        )
    upgrade_firmware_action(devId, fwInfo.fw_url)
    return {"message": "Firmware being upgraded", "devId": devId}

@router.get('/{devId}', response_model=Device)
async def get_device(devId: str, jwt: str = Depends(authenticate)) -> Device:
    device = device_db.getOne(device_db.qry.devId == devId)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device(devId:{devId}) does not exist"
        )
    return device

@router.delete('/{devId}')
async def del_device(devId: str, jwt: str = Depends(authenticate)) -> dict:
    device  = device_db.getOne(device_db.qry.devId == devId)    # this should be come before deletion
    doc_ids = device_db.delete(device_db.qry.devId == devId)
    if not doc_ids or len(doc_ids) == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device(devId:{devId}) does not exist"
        )
    if device['type'] == 'gateway':
        edges = device_db.get(device_db.qry.createdBy == devId)
        for edge in edges:
            device_db.delete(device_db.qry.devId == edge['devId'])
            delete_dynsec_role(edge['devId'])       # edge roles, edge device consists of role only
        delete_dynsec_role(devId)                   # gateway role
        delete_dynsec_device(devId)                 # gateway device
    elif device['type'] == 'edge':
        device_db.delete(device_db.qry.devId == devId)
        delete_dynsec_role(devId)
    else:
        device_db.delete(device_db.qry.devId == devId)
        delete_dynsec_device(devId)
        delete_dynsec_role(devId)
    return {"message": "Device deleted successfully", "devId": devId}

@router.get('/', response_model=List[Device])
async def get_devices(jwt: str = Depends(authenticate)) -> dict:
    return device_db.getAll()

@router.post('/')
async def add_device(newDevice: NewDevice, jwt: str = Depends(authenticate)) -> Device:
    if newDevice.devId.startswith('$') or newDevice.devId == 'admin':
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail = f"The Id({newDevice.devId}) can not be registered for Device/Gateway."
        )
    if not newDevice.type in ['gateway', 'edge', 'device']:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid Device Type({newDevice.type})"
        )
    qryDevice = device_db.getOne(device_db.qry.devId == newDevice.devId)
    qryApp = apps_db.getOne(apps_db.qry.appId == newDevice.devId)
    if qryDevice or qryApp:
        if qryApp:
            detail = f"The Id({newDevice.devId}) is already registered for AppId."
        else:
            detail = f"The Id({newDevice.devId}) is already registered for Device/Gateway."
        if type(jwt) == dict:
            # if jwt is dict, then it means it is called by REST API
            # if not, then it is called by MQTT
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=detail
            )
        else:
            logger.error(detail)
            return          # the edge device name is already taken

    if newDevice.type == 'edge':
        gw = device_db.getOne(device_db.qry.devId == newDevice.createdBy)
        if not gw or gw['type'] != 'gateway':
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid Gateway({newDevice.createdBy})"
            )
    newDevice.createdDate = newDevice.createdDate.replace(tzinfo=timezone.utc).astimezone(tz=kst)
    newDevice.createdDate = str(newDevice.createdDate.strftime('%Y-%m-%d %H:%M:%S'))
    device_db.insert(newDevice)
    add_dynsec_device(newDevice)
    return newDevice.dict()

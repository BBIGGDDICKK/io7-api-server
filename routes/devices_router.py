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
    """
    Remotely reboot a device by its ID.
    
    This endpoint sends a reboot command to the specified device.
    Authentication is required to access this endpoint.
    
    Caution:
    - The device will become temporarily unavailable during reboot
    - Any active operations on the device will be interrupted
    - Ensure the device is not performing critical tasks before rebooting
    
    Parameters:
    - devId: The unique identifier of the device to reboot
    
    Returns:
    - Confirmation message of the reboot command
    """
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
    """
    Reset a device to factory settings by its ID.
    
    This endpoint sends a factory reset command to the specified device.
    Authentication is required to access this endpoint.
    
    Caution:
    - This is a destructive operation that cannot be undone
    - All device configurations, data, and settings will be erased
    - The device will need to be reconfigured after reset
    - Only use this operation when absolutely necessary
    
    Parameters:
    - devId: The unique identifier of the device to factory reset
    
    Returns:
    - Confirmation message of the reset command
    """
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
    """
    Update the metadata for a specific device.
    
    This endpoint allows updating device metadata such as pubInterval, location, tags, or other attributes.
    Authentication is required to access this endpoint.
    
    Caution:
    - Ensure that the metadata format conforms to expected schema
    - Metadata changes may affect device behavior in applications
    
    Parameters:
    - devId: The unique identifier of the device to update
    - metaData: Dictionary containing the metadata to update
    
    Returns:
    - Confirmation message of the metadata update command
    """
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
    """
    Upgrade the firmware of a specific device.
    
    This endpoint triggers a firmware upgrade for the specified device using the provided firmware URL.
    Authentication is required to access this endpoint.
    
    Caution:
    - Ensure the firmware URL is secure (HTTPS) and trusted
    - Firmware upgrades may cause device downtime
    - Incorrect firmware can permanently damage the device
    - Always ensure firmware compatibility before upgrading
    - Do not interrupt the upgrade process once started
    
    Parameters:
    - devId: The unique identifier of the device to upgrade
    - fwInfo: Object containing the firmware URL and other information
    
    Returns:
    - Confirmation message of the firmware upgrade command
    """
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
    """
    Retrieve details for a specific device by ID.
    
    This endpoint returns all information about the device with the specified ID.
    Authentication is required to access this endpoint.
    
    Parameters:
    - devId: The unique identifier of the device to retrieve
    
    Returns:
    - A Device object containing all device details
    """
    device = device_db.getOne(device_db.qry.devId == devId)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device(devId:{devId}) does not exist"
        )
    return device

@router.delete('/{devId}')
async def del_device(devId: str, jwt: str = Depends(authenticate)) -> dict:
    """
    Delete a device from the system.
    
    This endpoint completely removes a device from the database and MQTT infrastructure.
    For gateway devices, it also removes all associated edge devices.
    Authentication is required to access this endpoint.
    
    Caution:
    - This operation cannot be undone
    - For gateway devices, all connected edge devices will also be deleted
    - All device access permissions will be permanently removed
    - Any services depending on this device will stop working
    
    Parameters:
    - devId: The unique identifier of the device to delete
    
    Returns:
    - Confirmation message with the deleted device ID
    """
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
    """
    Retrieve a list of all registered devices.
    
    This endpoint returns all devices registered in the system including gateways, edge devices, and regular devices.
    Authentication is required to access this endpoint.
    
    Returns:
    - A list of Device objects containing device details
    """
    return device_db.getAll()

@router.post('/')
async def add_device(newDevice: NewDevice, jwt: str = Depends(authenticate)) -> Device:
    """
    Register a new device in the system.
    
    This endpoint allows creation of new devices, edge devices, or gateways.
    Authentication is required to access this endpoint.
    
    Caution:
    - Device IDs cannot start with '$' or be named 'admin'
    - Device ID must be unique across both apps and devices
    - For edge devices, the createdBy field must reference a valid gateway
    - The device type must be one of 'gateway', 'edge', or 'device'
    - The password provided will be used for MQTT authentication
    
    Parameters:
    - newDevice: Object containing all required device information
    
    Returns:
    - The newly created Device object
    """
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

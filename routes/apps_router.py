from typing import List
from fastapi import APIRouter, HTTPException, status, Depends
from datetime import timezone, timedelta

from models import IOTApp, NewIOTApp, Device, MemberDevice
from secutils import authenticate
from environments import Database
from dynsec.apps_dynsec import add_dynsec_app, delete_dynsec_app, add_member, remove_member
from dynsec.roles_dynsec import delete_dynsec_role

apps_db = Database(IOTApp.Settings.name)
device_db = Database(Device.Settings.name)
router = APIRouter(tags=['Apps'])
kst=timezone(timedelta(hours=9))

@router.get('/', response_model=List[IOTApp])
async def get_apps(jwt: str = Depends(authenticate)) -> dict:
    """
    Retrieve a list of all registered IOT application IDs.
    
    This endpoint returns all application IDs registered in the system.
    The type of an application ID is IOTApp in io7 platform.
    Authentication is required to access this endpoint.
    
    Returns:
    - A list of IOTApp objects containing application details
    """
    return apps_db.getAll()

@router.post('/')
async def add_app(newApp: NewIOTApp, jwt: str = Depends(authenticate)) -> IOTApp:
    """
    Register a new IOT application ID in the system.
    
    This endpoint allows creation of a new application ID with the provided details.
    Authentication is required to access this endpoint.
    
    Caution:
    - Application IDs cannot start with '$' or be named 'admin'
    - Application ID must be unique across both apps and devices
    - The password provided will be used for MQTT authentication
    
    Returns:
    - The newly created IOTApp object
    """
    if newApp.appId.startswith('$') or newApp.appId == 'admin':
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail = f"The Id({newApp.appId}) can not be registered for AppId."
        )
    qryApp = apps_db.getOne(apps_db.qry.appId == newApp.appId)
    qryDevice = device_db.getOne(device_db.qry.devId == newApp.appId)
    if qryApp or qryDevice:
        if qryApp:
            detail = f"The Id({newApp.appId}) is already registered for AppId."
        else:
            detail = f"The Id({newApp.appId}) is already registered for Device."
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail
        )
    newApp.createdDate = newApp.createdDate.replace(tzinfo=timezone.utc).astimezone(tz=kst)
    newApp.createdDate = str(newApp.createdDate.strftime('%Y-%m-%d %H:%M:%S'))
    add_dynsec_app(newApp)
    apps_db.insert(newApp)
    return newApp.dict()

@router.get('/{appId}', response_model=IOTApp)
async def get_appId(appId: str, jwt: str = Depends(authenticate)) -> IOTApp:
    """
    Retrieve details for a specific IOT application ID.
    
    This endpoint returns the application details for the specified appId.
    Authentication is required to access this endpoint.
    
    Parameters:
    - appId: The unique identifier of the application to retrieve
    
    Returns:
    - An IOTApp object containing the application details
    """
    app = apps_db.getOne(apps_db.qry.appId == appId)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AppID(appId:{appId}) does not exist"
        )
    return app

@router.delete('/{appId}')
async def del_appId(appId: str, jwt: str = Depends(authenticate)) -> dict:
    """
    Delete an IOT application from the system.
    
    This endpoint removes the application ID with the specified appId from the database
    and also deletes the corresponding MQTT ACL and roles.
    Authentication is required to access this endpoint.
    
    Caution:
    - This operation cannot be undone
    - All device associations and access permissions will be permanently removed
    
    Parameters:
    - appId: The unique identifier of the application to delete
    
    Returns:
    - A confirmation message with the deleted application ID
    """
    app = apps_db.getOne(apps_db.qry.appId == appId)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AppId(appId:{appId}) does not exist"
        )
    
    if app.get('restricted', None):
        delete_dynsec_role(f'$apps_{appId}')
    delete_dynsec_app(appId)
    apps_db.delete(apps_db.qry.appId == appId)
    return {"message": "AppId deleted successfully", "appId": appId}

@router.put('/addMember/{appId}', response_model=IOTApp)
async def addMember(appId: str, member: MemberDevice, jwt: str = Depends(authenticate)) -> dict:
    """
    Add the device to the `appId`'s role, so the appId can access the device's event and command accordingly.

    When adding, the access to the evt & the cmd can be configured as needed. 
    For example, {evt : true} will allow access to the event from the device, and {evt : false} will deny.
    Likewise the command to the deivce can be configured. eg. {cmd : true}
    
    Caution:
    - Ensure proper access control to avoid security issues
    - Setting both evt and cmd to false effectively removes access
    
    Parameters:
    - appId: Application ID to grant access to
    - member: Device information including access permissions
    
    Returns:
    - Confirmation message with application and device IDs
    """
    app = apps_db.getOne(apps_db.qry.appId == appId)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AppId(appId:{appId}) does not exist"
        )

    add_member(appId, member.devId, member.evt, member.cmd)
    return {"message": "Device is added successfully", "appId": appId, "devId" : member.devId}

@router.put('/removeMember/{appId}', response_model=IOTApp)
async def removeMember(appId: str, devId: str, jwt: str = Depends(authenticate)) -> dict:
    """
    Removes the device from the `appId`'s role, so the `appId` can't access.
    
    This endpoint revokes the application's access to the specified device.
    Authentication is required to access this endpoint.
    
    Caution:
    - This operation cannot be undone
    - Any services depending on this access will stop working immediately
    
    Parameters:
    - appId: Application ID to revoke access from
    - devId: Device ID to remove access to
    
    Returns:
    - Confirmation message with application and device IDs
    """
    app = apps_db.getOne(apps_db.qry.appId == appId)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AppId(appId:{appId}) does not exist"
        )

    remove_member(appId, devId)
    return {"message": "Device is removed successfully", "appId": appId, "devId" : devId}
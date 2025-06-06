from typing import List
from fastapi import APIRouter, HTTPException, status, Depends
from datetime import timezone, timedelta

from models import IOTApp, NewIOTApp, Device, MemberDevice
from secutils import authenticate
from environments import Database
from dynsec.apps_dynsec import add_dynsec_app, delete_dynsec_app, add_member
from dynsec.roles_dynsec import delete_dynsec_role

apps_db = Database(IOTApp.Settings.name)
device_db = Database(Device.Settings.name)
router = APIRouter(tags=['Apps'])
kst=timezone(timedelta(hours=9))

@router.get('/', response_model=List[IOTApp])
async def get_apps(jwt: str = Depends(authenticate)) -> dict:
    return apps_db.getAll()

@router.post('/')
async def add_app(newApp: NewIOTApp, jwt: str = Depends(authenticate)) -> IOTApp:
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
    app = apps_db.getOne(apps_db.qry.appId == appId)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AppID(appId:{appId}) does not exist"
        )
    return app

@router.delete('/{appId}')
async def del_appId(appId: str, jwt: str = Depends(authenticate)) -> dict:
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
    print(appId)
    app = apps_db.getOne(apps_db.qry.appId == appId)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AppId(appId:{appId}) does not exist"
        )

    add_member(appId, member.devId, member.evt, member.cmd)
    return {"message": "Device is added successfully", "appId": appId, "devId" : "device"}
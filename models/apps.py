from typing import Optional
from datetime import datetime
from pydantic import BaseModel

class IOTApp(BaseModel):
    appId: str
    createdBy: str = 'admin'
    createdDate: datetime = datetime.utcnow()
    appDesc: Optional[str]
    restricted: bool = False

    class Config:
        schema_extra = {
            "example": {
                "appId": "str",
                "restricted": "false",
                "appDesc": "str",
                "createdBy": "str",
                "createdDate": "str"
            }
        }

    class Settings:
        name = "apps"


class NewIOTApp(IOTApp):
    password: str

    class Config:
        schema_extra = {
            "example": {
                "appId": "str",
                "password": "str",
                "restricted": "false",
                "appDesc": "str",
                "createdBy": "str",
                "createdDate": "str"
            }
        }
        fields = {'password': {'exclude': True}}


class MemberDevice(BaseModel):
    devId: str
    evt: bool
    cmd: bool

    class Config:
        schema_extra = {
            "example": {
                "devId": "str",
                "evt": "true",
                "cmd": "true",
            }
        }

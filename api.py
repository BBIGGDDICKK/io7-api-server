from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from mqtt_service import ws_manager, setup_mqtt
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
from environments import Settings
from routes.devices_router import router as devices_router
from routes.users_router import router as users_router
from routes.apps_router import router as apps_router

origins = ['*']

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)
settings = Settings()


@app.on_event("startup")
def startup():
    setup_mqtt()

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # 클라이언트에서 보내는 메시지 수신 시 처리 가능
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)

@app.get('/', include_in_schema=False)
async def welcome(request: Request) -> dict:
    return settings.TEMPLATES.TemplateResponse("home.html",
    {
        'request':request
    })

app.include_router(apps_router, prefix='/app-ids')
app.include_router(devices_router, prefix='/devices')
app.include_router(users_router, prefix='/users')

if __name__ == '__main__':
    if settings.SSL_CERT and os.path.exists(settings.SSL_CERT) and os.path.exists(settings.SSL_KEY):
        uvicorn.run(app, port=settings.PORT, host=settings.HOST,
                    ssl_keyfile=settings.SSL_KEY, ssl_certfile=settings.SSL_CERT)
    else:
        uvicorn.run(app, port=settings.PORT, host=settings.HOST)
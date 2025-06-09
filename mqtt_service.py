import paho.mqtt.client as mqtt
from fastapi import WebSocket
from typing import List
import asyncio

# WebSocket 연결을 관리할 객체
class WebSocketManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, msg: str):
        for ws in list(self.active):
            try:
                await ws.send_text(msg)
            except:
                self.disconnect(ws)

ws_manager = WebSocketManager()

# MQTT 콜백 함수들
def on_connect(client, userdata, flags, rc):
    print("✅ MQTT 연결됨, 구독 시작 rc=", rc)
    client.subscribe("topic/sensor")

def on_message(client, userdata, msg):
    payload = msg.payload.decode()
    print("🔹 MQTT 수신:", payload)
    asyncio.run(ws_manager.broadcast(payload))

def setup_mqtt():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect("mosquitto", 1883, 60) # 파라미터 broker ip, broker port, keepalive(클라이언트와 브로커 간의 “유효한 연결 유지 시간(초))
    client.loop_start()
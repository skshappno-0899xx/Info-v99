import asyncio
import time
import httpx
import json
import base64
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from Crypto.Cipher import AES
from google.protobuf import json_format, message
from google.protobuf.message import Message

# === Proto imports ===
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

# =============================================
# SETTINGS
# =============================================

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# =============================================
# 🌍 JWT TOKEN API
# =============================================

JWT_API_BASE = "https://shappno-deploy-hub.lovable.app/token"

# =============================================
# 🌍 ACCOUNT GROUPS (2টা)
# =============================================

ACCOUNTS = {
    "BD": {
        "uid": "5729559749",
        "password": "shappno_bXUX6Qf1"
    },
    "IND": {
        "uid": "5381645912",
        "password": "MINISTER_C2WHEZ-BOSSQKREQP"
    },
}

# কোন region কোন account group ব্যবহার করবে
REGION_TO_ACCOUNT = {
    # BD GROUP
    "BD":  "BD",
    "ID":  "BD",
    "ME":  "BD",
    "RU":  "BD",
    "PK":  "BD",
    "EU":  "BD",
    "VN":  "BD",
    # IND GROUP
    "IND": "IND",
    "BR":  "IND",
    "TH":  "IND",
}

# =============================================
# 🌍 SERVER URLS (region wise)
# =============================================

RELEASE_VERSION = "OB55"
DEFAULT_SERVER = "https://clientbp.ppmainecoonghj.com"

# JWT থেকে lock_region অনুযায়ী server বাছা হবে
REGION_SERVER_MAP = {
    "BD":  "https://clientbp.ppmainecoonghj.com",
    "IND": "https://client.ind.freefiremobile.com",
    "BR":  "https://client.us.freefiremobile.com",
    "TH":  "https://clientbp.ppmainecoonghj.com",
    "ID":  "https://clientbp.ppmainecoonghj.com",
    "ME":  "https://clientbp.ppmainecoonghj.com",
    "RU":  "https://clientbp.ppmainecoonghj.com",
    "PK":  "https://clientbp.ppmainecoonghj.com",
    "EU":  "https://clientbp.ppmainecoonghj.com",
    "VN":  "https://clientbp.ppmainecoonghj.com",
}

# =============================================
# 🌍 REGION PRIORITY
# =============================================

# BD group আগে → IND group → আবার BD group
REGION_PRIORITY = [
    "BD", "ID", "ME", "RU", "PK", "EU", "VN",   # BD group
    "IND", "BR", "TH",                          # IND group
    "BD", "ID", "ME", "RU", "PK", "EU", "VN",   # BD আবার fallback
]

REGION_PRIORITY_UNIQUE = ["BD", "ID", "ME", "RU", "PK", "EU", "VN", "IND", "BR", "TH"]

# === Flask App Setup ===

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# =============================================
# HELPER FUNCTIONS
# =============================================

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def unpad(text: bytes) -> bytes:
    padding_length = text[-1]
    if padding_length < 1 or padding_length > AES.block_size:
        return text
    return text[:-padding_length]

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(ciphertext)
    return unpad(decrypted)

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def decode_jwt_payload(token: str) -> dict:
    """JWT token এর payload decode করে"""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception as e:
        print(f"⚠️ JWT decode failed: {e}")
        return {}

# =============================================
# 🔑 JWT Token (account group অনুযায়ী)
# =============================================

async def get_jwt_token_for_account(account_key: str):
    """account_key = 'BD' বা 'IND'"""
    cred = ACCOUNTS.get(account_key)
    if not cred:
        return None

    url = f"{JWT_API_BASE}?uid={cred['uid']}&password={cred['password']}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            print(f"🔍 JWT API [{account_key}] status={response.status_code}")

            if response.status_code != 200:
                print(f"❌ JWT HTTP {response.status_code} for {account_key}")
                return None

            data = response.json()

            if data.get("status") != "success":
                print(f"❌ JWT status != success for {account_key}: {data}")
                return None

            token = data.get("token")
            if not token:
                print(f"❌ No token in response for {account_key}")
                return None

            # 🔓 JWT decode করে lock_region বের করি
            payload = decode_jwt_payload(token)
            lock_region = payload.get("lock_region", account_key).upper()
            release_version = payload.get("release_version", RELEASE_VERSION)

            print(f"🔓 JWT decoded: lock_region={lock_region}, release={release_version}")

            # lock_region অনুযায়ী সঠিক server বাছো
            server_url = REGION_SERVER_MAP.get(lock_region, DEFAULT_SERVER)

            print(f"✅ Token OK [{account_key}] → lock={lock_region}, server={server_url}")

            return {
                "token": f"Bearer {token}",
                "server_url": server_url,
                "release_version": release_version,
                "lock_region": lock_region,
                "expires_at": time.time() + 25200
            }
    except Exception as e:
        print(f"❌ JWT exception for {account_key}: {e}")
        return None

async def get_token_info(region: str):
    """region → account group → token"""
    region = region.upper()
    account_key = REGION_TO_ACCOUNT.get(region)
    if not account_key:
        print(f"❌ No account group for region {region}")
        return None, None, None

    # cache check
    info = cached_tokens.get(account_key)
    if info and time.time() < info['expires_at']:
        return info['token'], info['server_url'], info['release_version']

    # নতুন token আনি
    token_info = await get_jwt_token_for_account(account_key)
    if token_info:
        cached_tokens[account_key] = token_info
        return token_info['token'], token_info['server_url'], token_info['release_version']

    return None, None, None

async def initialize_tokens():
    """দুইটা account group এর জন্যই token আনি"""
    tasks = [get_jwt_token_for_account(k) for k in ACCOUNTS.keys()]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for key, res in zip(ACCOUNTS.keys(), results):
        if isinstance(res, dict):
            cached_tokens[key] = res

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

# =============================================
# Account Information Fetcher
# =============================================

async def GetAccountInformation(uid, unk, region, endpoint):
    try:
        payload = await json_to_proto(
            json.dumps({'a': int(uid), 'b': int(unk)}),
            main_pb2.GetPlayerPersonalShow()
        )
    except Exception as e:
        print(f"❌ Proto error: {e}")
        return None

    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    token, server, release_version = await get_token_info(region)
    account_key = REGION_TO_ACCOUNT.get(region.upper(), "?")
    print(f"🔍 [{region}] account={account_key} server={server}")

    if not token:
        print(f"❌ [{region}] No token available")
        return None

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': release_version or RELEASE_VERSION
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(server + endpoint, data=data_enc, headers=headers)

            print(f"🔍 [{region}] POST {server}{endpoint} → status={resp.status_code}, len={len(resp.content)}")

            if resp.status_code != 200:
                print(f"❌ [{region}] HTTP {resp.status_code}: {resp.content[:200]}")
                return None

            try:
                decrypted_data = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, resp.content)
                result = json.loads(json_format.MessageToJson(
                    decode_protobuf(decrypted_data, AccountPersonalShow_pb2.AccountPersonalShowInfo)
                ))
                print(f"✅ [{region}] decrypted OK")
                return result
            except Exception as e:
                print(f"⚠️ [{region}] decrypt failed: {e}, trying raw")
                result = json.loads(json_format.MessageToJson(
                    decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
                ))
                print(f"✅ [{region}] raw OK")
                return result
    except Exception as e:
        print(f"❌ [{region}] Request failed: {e}")
        return None

# === Caching Decorator ===

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# =============================================
# FLASK ROUTES
# =============================================

@app.route('/shappno')
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    region_param = request.args.get('region')

    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    # Manual region দেওয়া থাকলে
    if region_param:
        region = region_param.upper()
        try:
            return_data = asyncio.run(
                GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
            )
            if return_data and return_data.get("basicInfo"):
                uid_region_cache[uid] = region
                return json.dumps(return_data, indent=2, ensure_ascii=False), 200, \
                       {'Content-Type': 'application/json; charset=utf-8'}
            return jsonify({"error": f"No data for region {region}"}), 404
        except Exception as e:
            return jsonify({"error": f"Failed for region {region}: {str(e)}"}), 500

    # cached region আগে try
    if uid in uid_region_cache:
        try:
            return_data = asyncio.run(
                GetAccountInformation(uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow")
            )
            if return_data and return_data.get("basicInfo"):
                return json.dumps(return_data, indent=2, ensure_ascii=False), 200, \
                       {'Content-Type': 'application/json; charset=utf-8'}
        except Exception:
            pass

    # সব region try
    for region in REGION_PRIORITY:
        try:
            return_data = asyncio.run(
                GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
            )
            if return_data and return_data.get("basicInfo"):
                uid_region_cache[uid] = region
                print(f"🎯 Found UID {uid} in region {region}")
                return json.dumps(return_data, indent=2, ensure_ascii=False), 200, \
                       {'Content-Type': 'application/json; charset=utf-8'}
        except Exception as e:
            print(f"Failed {region}: {e}")
            continue

    return jsonify({"error": "UID not found in any region."}), 404

@app.route('/regions', methods=['GET'])
def get_regions():
    return jsonify({
        "accounts": {k: {"uid": v["uid"]} for k, v in ACCOUNTS.items()},
        "region_to_account": REGION_TO_ACCOUNT,
        "priority": REGION_PRIORITY_UNIQUE,
        "region_server_map": REGION_SERVER_MAP,
        "default_server": DEFAULT_SERVER,
        "release_version": RELEASE_VERSION
    })

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all account groups.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

@app.route('/token-status', methods=['GET'])
def token_status():
    status = {}
    for account_key, info in cached_tokens.items():
        if info and 'expires_at' in info:
            remaining = max(0, info['expires_at'] - time.time())
            status[account_key] = {
                'valid': info['expires_at'] > time.time(),
                'expires_in': f"{int(remaining // 3600)}h {int((remaining % 3600) // 60)}m",
                'lock_region': info.get('lock_region'),
                'server_url': info.get('server_url'),
                'release_version': info.get('release_version')
            }
    return jsonify(status)

@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "version": RELEASE_VERSION,
        "endpoint": "/shappno?uid=UID",
        "example": "/shappno?uid=4740045744",
        "accounts": list(ACCOUNTS.keys()),
        "priority": " → ".join(REGION_PRIORITY_UNIQUE),
        "jwt_api": JWT_API_BASE
    })

# === Startup ===

async def startup():
    print("🔄 Initializing JWT tokens...")
    await initialize_tokens()
    print("✅ Tokens initialized!")
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5020, debug=False)
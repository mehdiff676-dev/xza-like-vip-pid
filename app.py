from flask import Flask, request, jsonify
import sys
import os
import json
import requests
import binascii
import time
import urllib3
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
from concurrent.futures import ThreadPoolExecutor, as_completed

# إخفاء تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# استدعاء ملفات البروتو
import like_pb2
import like_count_pb2
import like
import output_pb2
import my_pb2
from xLiKex_ProTo import *

# ================ الإعدادات الأساسية ================
app = Flask(__name__)

ACCOUNTS_FILE = 'tokens.json'
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# إعدادات الجلسة
SESSION = requests.Session()
SESSION.verify = False
adapter = requests.adapters.HTTPAdapter(
    pool_connections=300,
    pool_maxsize=300,
    max_retries=1,
    pool_block=False
)
SESSION.mount('https://', adapter)
SESSION.mount('http://', adapter)

DEFAULT_MAX_WORKERS = min(150, (os.cpu_count() or 1) * 25)

# ================ دوال المساعدة ================
def log_debug(msg):
    print(f"[DEBUG] {msg}")

def log_error(msg):
    print(f"[ERROR] {msg}")

# ================ دوال التوكن والحسابات ================
def getGuestAccessToken(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    try:
        resp = SESSION.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                            headers=headers, data=data, timeout=3)
        data_response = resp.json()
    except Exception as e:
        return {"error": "request_failed"}

    if data_response.get("success") is True:
        resp_obj = data_response.get("response", {})
        if resp_obj.get("error") == "auth_error":
            return {"error": "auth_error"}
    return {"access_token": data_response.get("access_token"), "open_id": data_response.get("open_id")}

def check_guest(uid, password):
    token_data = getGuestAccessToken(uid, password)
    if token_data.get("error") == "auth_error":
        return uid, None, None, True
    access_token = token_data.get("access_token")
    open_id = token_data.get("open_id")
    if access_token and open_id:
        return uid, access_token, open_id, False
    return uid, None, None, False

def login(uid, access_token, open_id, platform_type):
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    game_data = my_pb2.GameData()
    game_data.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "Free Fire"
    game_data.game_version = 1
    game_data.version_code = "1.115.1"
    game_data.os_info = "iOS 26"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1170
    game_data.screen_height = 2532
    game_data.dpi = "1000"
    game_data.cpu_info = "Apple A15 Bionic"
    game_data.total_ram = 6144
    game_data.gpu_name = "Apple GPU (5-core)"
    game_data.gpu_version = "Metal 3"
    game_data.user_id = uid
    game_data.ip_address = "172.190.111.97"
    game_data.language = "ar"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = 4
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)

    try:
        serialized_data = game_data.SerializeToString()
    except Exception as e:
        return None

    padded_data = pad(serialized_data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(padded_data)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB52",
        "Content-Length": str(len(encrypted_data))
    }
    try:
        response = SESSION.post(url, data=encrypted_data, headers=headers, timeout=6)
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            try:
                jwt_msg.ParseFromString(response.content)
            except Exception as e:
                return None
            if jwt_msg.token:
                return jwt_msg.token
    except Exception as e:
        return None
    return None

def load_accounts():
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        # إذا الملف مش موجود، ننشئه
        save_accounts({})
        return {}
    except Exception:
        return {}

def save_accounts(accounts):
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2)

def get_tokens_local_sync(retries_per_account: int = 1, platform_type: int = 4):
    accounts = load_accounts()
    tokens = []
    if not isinstance(accounts, dict):
        return tokens

    with ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS, thread_name_prefix="TokenWorker") as executor:
        future_to_uid = {}
        for uid, password in accounts.items():
            future = executor.submit(process_single_account, uid, password, retries_per_account, platform_type)
            future_to_uid[future] = uid
        
        for future in as_completed(future_to_uid):
            token = future.result()
            if token:
                tokens.append(token)
    
    return tokens

def process_single_account(uid, password, retries_per_account, platform_type):
    for attempt in range(retries_per_account):
        try:
            uid_str, access_token, open_id, err_flag = check_guest(uid, password)
            if err_flag:
                break
            if not access_token or not open_id:
                continue
            jwt_token = login(uid_str, access_token, open_id, platform_type)
            if jwt_token:
                return jwt_token
        except Exception as e:
            time.sleep(0.05)
    return None

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode()

def create_uid_proto(uid):
    pb = like.uid_generator()
    pb.saturn_ = int(uid)
    pb.garena = 1
    return pb.SerializeToString()

def create_like_proto(uid):
    pb = like_pb2.like()
    pb.uid = int(uid)
    return pb.SerializeToString()

def decode_protobuf(binary):
    try:
        pb = like_count_pb2.Info()
        pb.ParseFromString(binary)
        return pb
    except DecodeError:
        return None

def make_request(enc_uid, token):
    url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"
    }
    try:
        res = SESSION.post(url, data=bytes.fromhex(enc_uid), headers=headers, timeout=4)
        return decode_protobuf(res.content)
    except Exception as e:
        return None

def send_like_with_token(enc_like_hex, token, timeout=3):
    url = "https://clientbp.ggpolarbear.com/LikeProfile"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"
    }
    try:
        r = SESSION.post(url, data=bytes.fromhex(enc_like_hex), headers=headers, timeout=timeout)
        return r.status_code
    except Exception as e:
        return None

def send_likes_threaded(uid, tokens, max_workers=None):
    if max_workers is None:
        max_workers = DEFAULT_MAX_WORKERS
        
    enc_like_hex = encrypt_message(create_like_proto(uid))
    results = []
    if not tokens:
        return results
    
    workers = min(max_workers, len(tokens))

    batch_size = 100
    token_batches = [tokens[i:i + batch_size] for i in range(0, len(tokens), batch_size)]
    
    for batch in token_batches:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="LikeWorker") as ex:
            futures = [ex.submit(send_like_with_token, enc_like_hex, t) for t in batch]
            for fut in futures:
                try:
                    status = fut.result(timeout=4)
                    results.append(status)
                except Exception:
                    results.append(None)
    
    return results

def send_likes_until_100(uid, tokens):
    enc_uid = encrypt_message(create_uid_proto(uid))
    
    before = make_request(enc_uid, tokens[0])
    if not before:
        return 0, 0, 0, "Unknown", 0
    
    before_data = json.loads(MessageToJson(before))
    likes_before = int(before_data.get("AccountInfo", {}).get("Likes", 0))
    nickname = before_data.get("AccountInfo", {}).get("PlayerNickname", "Unknown")
    
    target_likes = 100
    total_added = 0
    success_count = 0
    attempts = 0
    
    while total_added < target_likes and attempts < 10:
        attempts += 1
        responses = send_likes_threaded(uid, tokens, max_workers=150)
        round_success = sum(1 for r in responses if r == 200)
        success_count += round_success
        
        time.sleep(1)
        after = make_request(enc_uid, tokens[0])
        
        if after:
            after_data = json.loads(MessageToJson(after))
            likes_after = int(after_data.get("AccountInfo", {}).get("Likes", 0))
            round_added = likes_after - likes_before - total_added
            if round_added > 0:
                total_added += round_added
            else:
                break
        
        if total_added >= target_likes:
            break
    
    return total_added, likes_before, likes_before + total_added, nickname, success_count

# ================ دوال إدارة الحسابات ================
def add_account(uid, password):
    """إضافة حساب جديد"""
    accounts = load_accounts()
    accounts[str(uid)] = str(password)
    save_accounts(accounts)
    return True

def remove_account(uid):
    """حذف حساب"""
    accounts = load_accounts()
    if str(uid) in accounts:
        del accounts[str(uid)]
        save_accounts(accounts)
        return True
    return False

def get_accounts_list():
    """جلب قائمة الحسابات"""
    return load_accounts()

# ================ مسارات API ================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "online",
        "message": "Free Fire Likes API",
        "endpoints": {
            "/like?uid=ID": "إرسال لايكات لـ ID",
            "/add_account": "إضافة حساب (POST)",
            "/remove_account": "حذف حساب (POST)",
            "/accounts": "عرض الحسابات",
            "/stats": "إحصائيات"
        }
    })

@app.route('/like', methods=['GET'])
def send_likes():
    """إرسال لايكات لـ ID معين"""
    uid = request.args.get('uid')
    
    if not uid:
        return jsonify({
            "success": False,
            "error": "يرجى إرسال uid",
            "example": "/like?uid=12345678"
        }), 400
    
    try:
        # جلب التوكنات
        tokens = get_tokens_local_sync(retries_per_account=1)
        
        if not tokens:
            return jsonify({
                "success": False,
                "error": "لا توجد توكنات صالحة"
            }), 500
        
        # إرسال اللايكات
        likes_added, likes_before, likes_after, nickname, success_count = send_likes_until_100(uid, tokens)
        
        if likes_added == 0:
            return jsonify({
                "success": False,
                "error": "لا يمكن إرسال لايكات الآن، حاول مرة أخرى خلال 24 ساعة",
                "uid": uid,
                "nickname": nickname
            })
        
        return jsonify({
            "success": True,
            "uid": uid,
            "nickname": nickname,
            "likes_before": likes_before,
            "likes_after": likes_after,
            "likes_added": likes_added,
            "successful_requests": success_count
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/add_account', methods=['POST'])
def add_account_route():
    """إضافة حساب جديد (يستقبل JSON)"""
    data = request.get_json()
    
    if not data:
        return jsonify({
            "success": False,
            "error": "يرجى إرسال JSON"
        }), 400
    
    uid = data.get('uid')
    password = data.get('password')
    
    if not uid or not password:
        return jsonify({
            "success": False,
            "error": "يرجى إرسال uid و password"
        }), 400
    
    try:
        add_account(uid, password)
        return jsonify({
            "success": True,
            "message": f"تم إضافة الحساب {uid} بنجاح"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/remove_account', methods=['POST'])
def remove_account_route():
    """حذف حساب"""
    data = request.get_json()
    
    if not data:
        return jsonify({
            "success": False,
            "error": "يرجى إرسال JSON"
        }), 400
    
    uid = data.get('uid')
    
    if not uid:
        return jsonify({
            "success": False,
            "error": "يرجى إرسال uid"
        }), 400
    
    if remove_account(uid):
        return jsonify({
            "success": True,
            "message": f"تم حذف الحساب {uid} بنجاح"
        })
    else:
        return jsonify({
            "success": False,
            "error": f"الحساب {uid} غير موجود"
        }), 404

@app.route('/accounts', methods=['GET'])
def list_accounts():
    """عرض جميع الحسابات"""
    accounts = get_accounts_list()
    return jsonify({
        "success": True,
        "total": len(accounts),
        "accounts": accounts
    })

@app.route('/stats', methods=['GET'])
def stats():
    """إحصائيات عامة"""
    accounts = get_accounts_list()
    return jsonify({
        "success": True,
        "total_accounts": len(accounts),
        "status": "running"
    })

# ================ تشغيل التطبيق ================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
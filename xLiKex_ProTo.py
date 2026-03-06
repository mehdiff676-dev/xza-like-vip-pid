import requests, binascii, time, warnings, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from colorama import Fore, Style, init
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import output_pb2, my_pb2

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

SESSION = requests.Session()
SESSION.verify = False

def log_debug(msg):
    print(f"[DEBUG] {msg}")

def log_error(msg):
    print(f"[ERROR] {msg}")

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
                            headers=headers, data=data, timeout=12)
        data_response = resp.json()
    except Exception as e:
        log_error(f"getGuestAccessToken request error for uid {uid}: {e}")
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
        log_debug(f"UID {uid}: guest login OK (access_token obtained).")
        return uid, access_token, open_id, False
    log_debug(f"UID {uid}: guest login failed or missing token.")
    return uid, None, None, False

def login(uid, access_token, open_id, platform_type):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
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
        log_error(f"Serialize error for uid {uid}: {e}")
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
        "ReleaseVersion": "OB50",
        "Content-Length": str(len(encrypted_data))
    }
    try:
        response = SESSION.post(url, data=encrypted_data, headers=headers, timeout=18)
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            try:
                jwt_msg.ParseFromString(response.content)
            except Exception as e:
                log_debug(f"UID {uid}: failed parse JWT response.")
                return None
            if jwt_msg.token:
                log_debug(f"UID {uid}: login succeeded (JWT obtained).")
                return jwt_msg.token
        else:
            log_debug(f"UID {uid}: MajorLogin returned status {response.status_code}.")
    except Exception as e:
        log_error(f"UID {uid}: error during MajorLogin request: {e}")
    return None

def load_accounts():
    try:
        return json.load(open(ACCOUNTS_FILE, "r", encoding="utf-8"))
    except Exception:
        return {}

def get_tokens_local_sync(retries_per_account: int = 2, platform_type: int = 4):
    accounts = load_accounts()
    tokens = []
    if not isinstance(accounts, dict):
        log_error("Accounts file format invalid (expected JSON object).")
        return tokens

    for uid, password in accounts.items():
        success = False
        for attempt in range(retries_per_account):
            try:
                uid_str, access_token, open_id, err_flag = check_guest(uid, password)
                if err_flag:
                    log_debug(f"UID {uid}: invalid guest credentials.")
                    break
                if not access_token or not open_id:
                    log_debug(f"UID {uid}: no access_token/open_id from guest (attempt {attempt+1}).")
                    continue
                jwt_token = login(uid_str, access_token, open_id, platform_type)
                if jwt_token:
                    tokens.append(jwt_token)
                    success = True
                    break
            except Exception as e:
                log_error(f"UID {uid}: exception while obtaining token (attempt {attempt+1}): {e}")
                time.sleep(0.5)
        if not success:
            log_debug(f"UID {uid}: token not obtained after {retries_per_account} attempts.")
    log_debug(f"Collected {len(tokens)} valid tokens from local accounts.")
    return tokens
from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import Fore, Style, init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
from serverless_wsgi import handle_request  # للتكامل مع Vercel

# تعطيل تحذيرات SSL
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# إعدادات التشفير
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# تهيئة Colorama
init(autoreset=True)

# تهيئة تطبيق Flask
app = Flask(__name__)

# إعداد التخزين المؤقت
cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 25200  # 7 ساعات
})

def get_token(password, uid):
    """
    الحصول على توكن من الخدمة الخارجية
    """
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(Fore.RED + f"Error getting token: {e}")
        return None

def encrypt_message(key, iv, plaintext):
    """
    تشفير البيانات باستخدام AES-CBC
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def load_tokens(file_path, limit=None):
    """
    تحميل التوكنات من ملف JSON
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
        return list(data.items())[:limit] if limit else list(data.items())

def parse_response(response_content):
    """
    تحليل الرد من الخادم
    """
    return {
        key.strip(): value.strip().strip('"')
        for line in response_content.split("\n")
        if ":" in line
        for key, value in [line.split(":", 1)]
    }

def process_token(uid, password):
    """
    معالجة التوكن وإنشاء بيانات اللعبة
    """
    token_data = get_token(password, uid)
    if not token_data:
        return {"uid": uid, "error": "فشل في الحصول على التوكن"}
    
    # إنشاء كائن GameData Protobuf
    game_data = my_pb2.GameData()
    
    # تعبئة بيانات اللعبة (مثال)
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.open_id = token_data.get('open_id', '')
    game_data.access_token = token_data.get('access_token', '')
    # ... (تعبئة جميع الحقول المطلوبة)
    
    # تشفير البيانات وإرسالها
    encrypted_data = encrypt_message(AES_KEY, AES_IV, game_data.SerializeToString())
    
    try:
        response = requests.post(
            "https://loginbp.common.ggbluefox.com/MajorLogin",
            data=binascii.hexlify(encrypted_data),
            headers={
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                'Content-Type': "application/octet-stream"
            },
            verify=False
        )
        
        if response.status_code == 200:
            parsed_response = output_pb2.Garena_420()
            parsed_response.ParseFromString(response.content)
            return parse_response(str(parsed_response))
        else:
            return {"error": f"خطأ في الخادم: {response.status_code}"}
            
    except Exception as e:
        return {"error": f"خطأ في الاتصال: {e}"}

@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200)
def get_responses():
    """
    نقطة النهاية الرئيسية
    """
    limit = request.args.get('limit', default=1, type=int)
    tokens = load_tokens("accs.txt", limit)
    
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_token, uid, pwd): uid for uid, pwd in tokens}
        for future in as_completed(futures):
            results.append(future.result())
    
    return jsonify(results)

# دالة التشغيل لـ Vercel
def vercel_handler(event, context):
    return handle_request(app, event, context)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=50011)
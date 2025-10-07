from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
import requests
from rest_framework_simplejwt.tokens import RefreshToken
import logging
import os
from urllib.parse import urljoin
from datetime import datetime
import certifi

# Logger สำหรับการ Debug
logger = logging.getLogger(__name__)
BASE_AUTH_URL = os.getenv('AUTH_URL')
AUTH_PRIVATE_KEY = os.getenv('AUTH_PRIVATE_KEY')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY')
VERIFY_CERTIFICATE = os.getenv('VERIFY_CERTIFICATE',True).lower() in ('true', '1', 't') 

# Telegram
BOT_TOKEN = os.getenv('BOT_TOKEN')
CHAT_ID = os.getenv('CHAT_ID')

os.environ['SSL_CERT_FILE'] = certifi.where()

class LoginSerializer(serializers.Serializer):

    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    # recaptcha_token = serializers.CharField()  # เพิ่ม field นี้เข้ามา

    def validate(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password")
        # recaptcha_token = attrs.get("recaptcha_token")

        def telegramAPI(message):
            now = datetime.now()
            time_stamps = now.strftime("%d/%b/%Y %H:%M:%S")
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
            text = f"{message}\n\nTimestamps: {time_stamps}"
            params = {
                "chat_id": CHAT_ID,
                "text": text
            }
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()
            except requests.exceptions.HTTPError as err:
                print(f"เกิดข้อผิดพลาดในการส่งข้อความ: {err}")


            except Exception as err:
                print(f"เกิดข้อผิดพลาดที่ไม่ทราบสาเหตุ: {err}")

        # print(username,password,recaptcha_token)
        # 1. ตรวจสอบ reCAPTCHA Token กับ Google ก่อน
        # google_recaptcha_url = "https://www.google.com/recaptcha/api/siteverify"
        # recaptcha_secret_key = RECAPTCHA_SECRET_KEY # ใส่ Secret Key ของคุณ
        
        # print(recaptcha_secret_key)
        # recaptcha_response = requests.post(
        #     google_recaptcha_url,
        #     data={'secret': recaptcha_secret_key, 'response': recaptcha_token}
        # )
        # print(recaptcha_response)
        # recaptcha_result = recaptcha_response.json()
        
        # if not recaptcha_result.get("success"):
        #     raise serializers.ValidationError({"recaptcha": "Failed reCAPTCHA verification."})
            
        # print(username,password)
        # URL ของ Server ภายนอก
        auth_url =  urljoin(BASE_AUTH_URL,"api/login")
        # print("auth_url",auth_url)
        # print(auth_url)
        
        headers = {
            "Authorization" : f"Bearer {AUTH_PRIVATE_KEY}",
            'Content-Type' : "application/json",
        }

        print("🔐 Using CA cert at:", certifi.where())
        try:
            # ส่งข้อมูลไปตรวจสอบกับ Server ภายนอก
            response = requests.post(
                auth_url, 
                headers=headers,
                json={'username': username, 'password': password},
                verify=VERIFY_CERTIFICATE
                # verify=certifi.where()
            )
            print("Success ✅", response.status_code)

            # ถ้า Status Code เป็น 200 (OK)
            external_user_data = response.json()
            if response.status_code == 200:
                refresh = RefreshToken()
                refresh['username'] = username
                refresh['user_data'] = external_user_data["data"]['user']
                # print(external_user_data["status"])
                if external_user_data["status"] == True:
                    message = f"Login Successful!\nUsername: {username}\nFullname: {external_user_data["data"]['user']["fullname"]}"
                    telegramAPI(message)

                return {
                    'auth_token': external_user_data['data']['access_token'],
                    'refresh': str(refresh),
                    'access' : str( refresh.access_token ),
                    'user_data' : external_user_data["data"]['user'],
                    'status' : external_user_data["status"],
                    'expires_in' : external_user_data["data"]['expires_at']
                }
               
            elif response.status_code == 401:
                message = f"Username: {username}\nMessage: trying to Login"
                telegramAPI(message)
                return response.json()
            else:
                # ถ้า Status Code ไม่ใช่ 200 ให้ throw exception
                # พร้อมส่งข้อมูล error จาก server ภายนอก
                error_data = response.json()
                telegramAPI( error_data )
                raise AuthenticationFailed(detail=error_data)

        except requests.exceptions.RequestException as e:
            logger.error(f"API request to external server failed: {str(e)}")
            message = f"API request to external server failed\n{e}"
            telegramAPI(message)
            raise AuthenticationFailed(detail={"message": "ไม่สามารถติดต่อ Server ภายนอกได้"})
        # except requests.exceptions.SSLError as e:
        #     print("SSL Error ❌")
        #     print(e)
        #     message = f"SSL Error during external request: {str(e)}"
        #     logger.error(message)
        #     raise AuthenticationFailed(detail={"message": message})

    
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
import requests
from rest_framework_simplejwt.tokens import RefreshToken
import logging
import os
from urllib.parse import urljoin

# Logger สำหรับการ Debug
logger = logging.getLogger(__name__)
BASE_AUTH_URL = os.getenv('AUTH_URL')
AUTH_PRIVATE_KEY = os.getenv('AUTH_PRIVATE_KEY')

class LoginSerializer(serializers.Serializer):

    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    def validate(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password")

        # print(username,password)
        # URL ของ Server ภายนอก
        auth_url =  urljoin(BASE_AUTH_URL,"api/login")
        # print("auth_url",auth_url)
        # print(auth_url)
        
        headers = {
            "Authorization" : f"Bearer {AUTH_PRIVATE_KEY}",
            'Content-Type' : "application/json",
        }
        # print(headers)
        try:
            # ส่งข้อมูลไปตรวจสอบกับ Server ภายนอก
            response = requests.post(auth_url, headers=headers,json={'username': username, 'password': password})
            # ถ้า Status Code เป็น 200 (OK)
            external_user_data = response.json()
            # print(external_user_data)
            if response.status_code == 200:
                refresh = RefreshToken()
                refresh['username'] = username
                refresh['user_data'] = external_user_data["data"]['user']
                
                return {
                    'auth_token': external_user_data['data']['access_token'],
                    'refresh': str(refresh),
                    'access' : str( refresh.access_token ),
                    'user_data' : external_user_data["data"]['user'],
                    'status' : external_user_data["status"],
                    'expires_in' : external_user_data["data"]['expires_at']
                }
            elif response.status_code == 401:
                return response.json()
            else:
                # ถ้า Status Code ไม่ใช่ 200 ให้ throw exception
                # พร้อมส่งข้อมูล error จาก server ภายนอก
                error_data = response.json()
                raise AuthenticationFailed(detail=error_data)

        except requests.exceptions.RequestException as e:
            logger.error(f"API request to external server failed: {str(e)}")
            raise AuthenticationFailed(detail={"message": "ไม่สามารถติดต่อ Server ภายนอกได้"})
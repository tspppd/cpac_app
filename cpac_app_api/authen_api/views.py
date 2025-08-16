from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
import os
from dotenv import load_dotenv
from urllib.parse import urljoin
import logging
logger = logging.getLogger(__name__)
load_dotenv()

BASE_AUTH_URL = os.getenv('AUTH_URL')
AUTH_PRIVATE_KEY = os.environ.get('AUTH_PRIVATE_KEY')



login_url = urljoin(BASE_AUTH_URL,'api/login') # ลงชื่อเข้าใช้ / POST
register_url = urljoin(BASE_AUTH_URL,"/api/register") # ลงทะเบียน / POST
logout_url = urljoin(BASE_AUTH_URL,'/api/logout') # ออกจากระบบ / POST
user_url = urljoin(BASE_AUTH_URL,'/api/users') # ข้อมูลผู้ใช้งานทั้งหมด / GET
userProfile_url = urljoin(BASE_AUTH_URL,"/api/profile") # ข้อมูลผู้ใช้งานปัจจุบัน / GET


class LoginAPIView(APIView):
    def post(self, request):
        # รับ username และ password จาก body
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # เรียก auth_login แล้วส่งค่ากลับ
        auth_response = self.auth_login(username, password)
        # print('auth_response',auth_response)
        if auth_response is None:
            return Response('Username Password invalid', status=status.HTTP_400_BAD_REQUEST)
        if auth_response is not None:
            if auth_response['status']:
                # print('Auth pass')
                access_token = auth_response['data']['access_token']
                # print('access_token',access_token)
                response = Response(auth_response['data']['user'], status=status.HTTP_200_OK)
                # print(response)
                response.set_cookie( 
                    key='access_token',
                    value=access_token,
                    httponly=True, # Production : True
                    secure=True, # Production : True
                    samesite="None", # Production : "None" , Dev : "Lax", "Strict"
                    max_age=604800, # <--- กำหนดอายุ 7 วัน (7*24*60*60 วินาที)
                    path='/'
                )
            else: 
                response = Response(auth_response, status=status.HTTP_200_OK)

            return response

            # return Response(auth_response, status=status.HTTP_200_OK)


    def auth_login(self, username, password):
        headers = {
            "Authorization": f"Bearer {AUTH_PRIVATE_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "username": username,
            "password": password
        }

        response = requests.post( login_url , headers=headers, json=data)
        return response.json()


class RegisterAPIView(APIView):
    def post(self, request):
        if not request.data:
            return Response({'error': 'Invalid Data'}, status=status.HTTP_400_BAD_REQUEST)
        
        auth_response = self.auth_register(request)
        
        # auth_register จะคืนค่าเป็น tuple (data, status_code)
        response_data, response_status = auth_response
        
        return Response(response_data, status=response_status)
    
    
    def auth_register(self, request):
        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return {"error": "Authorization token required"}, status.HTTP_401_UNAUTHORIZED

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        try:
            data = request.data
            response = requests.post(register_url, headers=headers, json=data)
            
            # ถ้า Status Code เป็น 2xx ให้คืนค่า JSON ที่ได้
            if response.ok:
                return response.json(), response.status_code
            
            # ถ้า Status Code เป็น 4xx หรือ 5xx ให้คืนค่า JSON Error และ Status Code นั้นๆ
            else:
                return response.json(), response.status_code

        # จัดการเฉพาะ HTTPError ที่เกิดจาก response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            # ดึง error JSON จาก response แล้วส่งกลับไป
            return e.response.json(), e.response.status_code
        
        # จัดการ RequestException อื่นๆ (เช่น Network Error)
        except requests.exceptions.RequestException as e: 
            logger.error(f"Network error during registration: {str(e)}")
            return {
                "error": "การเชื่อมต่อล้มเหลว",
                "details": "ไม่สามารถติดต่อเซิร์ฟเวอร์หลักได้"
            }, status.HTTP_500_INTERNAL_SERVER_ERROR
        
        # จัดการ Exception อื่นๆ ที่ไม่คาดคิด
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {
                "error": "เกิดข้อผิดพลาดไม่ทราบสาเหตุ",
                "details": str(e)
            }, status.HTTP_500_INTERNAL_SERVER_ERROR


class LogoutAPIView(APIView):
    def post(self, request):
        response = Response({'message':"Logout Successful"}, status=status.HTTP_200_OK)
        response.delete_cookie(
            key='access_token',
            path='/',
            samesite="None",
 
        )
        return response
        

class UsersAPIView(APIView):
    def get(self,request):
        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.get(user_url,headers=headers)
            response.raise_for_status()
            try:
                users = response.json()
            except ValueError:
                return Response(
                    {"error": "Invalid JSON in response from user API"},
                    status=status.HTTP_502_BAD_GATEWAY
                )
            return Response( users  # ✅ return รายชื่อ user กลับไปด้วย
            , status=status.HTTP_200_OK)
        except requests.HTTPError as http_err:
            return Response(
                {
                    "error": "User API returned an error",
                    "status_code": response.status_code,
                    "details": str(http_err)
                },
                status=response.status_code
            )
        except requests.RequestException as e:
            return Response({
                "error": "Getusers failed",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfileAPIView(APIView):
    def get(self,request):

        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return Response({'error':'Token not Provided'},status=status.HTTP_401_UNAUTHORIZED)
        try:
            headers={
                "Authorization":f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            response = requests.get(userProfile_url, headers=headers)
            currentUser = response.json()
            return Response(currentUser  # ✅ return รายชื่อ user กลับไปด้วย
            , status=status.HTTP_200_OK)
        except requests.RequestException as e :
            return Response({
                "error": "Getusers failed",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ManageuserAPIView(APIView):
    def get(self,request,userId):
        userId_url = urljoin(BASE_AUTH_URL,f"/api/users/{userId}") # ข้อมูลผู้ใช้งานตาม id / GET, PATCH,DELETE

        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)

        headers={
            "Authorization":f"Bearer {access_token}",
            "Content-Type":"application/json"
        }
        try:
            response = requests.get(userId_url,headers=headers)
            response.raise_for_status()
            user = response.json()
            return Response( user  # ✅ return รายชื่อ user กลับไปด้วย
            , status=status.HTTP_200_OK)

        except requests.RequestException as e:
            return Response({
                "error": "Getusers failed",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def patch(self,request,userId):
        userId_url = urljoin(BASE_AUTH_URL,f"/api/users/{userId}") # ข้อมูลผู้ใช้งานตาม id / GET, PATCH,DELETE
        
        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)


        headers={
            "Authorization":f"Bearer {access_token}",
            "Content-Type":"application/json"
        }
        
        data = request.data
        if not data:
            return Response({"error": "No data provided for update"}, status=status.HTTP_400_BAD_REQUEST)
        
        # logger = logging.getLogger(__name__)
        # try:
        #     data = request.data.copy()
        #     data.pop("password",None)
        #     data.pop("password_confirmation",None)
        # except Exception as e:
        #     logger.error(f"Error processing request data: {str(e)}")
        #     return {"error": "Invalid data format"}
        try:
            response = requests.patch(userId_url,headers=headers,json=data)
            if not response.ok:
                return Response(response.text, status=response.status_code)
            response.raise_for_status()
            edit_user = response.json()
            return Response( edit_user , status=status.HTTP_200_OK)

        except requests.RequestException as e: 
            return Response({
                "error": "Edit user failed",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, userId):
        userId_url = urljoin(BASE_AUTH_URL,f"/api/users/{userId}") # ข้อมูลผู้ใช้งานตาม id / GET, PATCH,DELETE
        # ดึง token จาก header
        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)


        headers = {
            "Authorization":f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        try:
            # เรียก API ภายนอกเพื่อลบ user
            response = requests.delete(userId_url, headers=headers)
            response.raise_for_status()
            return Response(response, status=status.HTTP_200_OK)
        
        except requests.HTTPError as e:
            # ดึงข้อความจาก API ภายนอกถ้ามี
            error_detail = e.response.text if e.response is not None else str(e)
            return Response({
                "error": "Delete user failed",
                "details": error_detail
            }, status=e.response.status_code if e.response else status.HTTP_500_INTERNAL_SERVER_ERROR)
        except requests.RequestException as e:
            return Response({
                "error": "Request to auth server failed",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
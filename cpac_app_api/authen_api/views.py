from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
import os
from dotenv import load_dotenv
from urllib.parse import urljoin
import logging
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer


logger = logging.getLogger(__name__)
load_dotenv()

BASE_AUTH_URL = os.getenv('AUTH_URL',"https://test-auth.cpacworkspace.com/")
AUTH_PRIVATE_KEY = os.environ.get('AUTH_PRIVATE_KEY')
API_AUTH_TOKEN = os.getenv('API_AUTH_TOKEN',"auth_token")
SECURE_COOKIE = os.getenv('SECURE_COOKIE',True)
SAMSITE_COOKIE = os.getenv('SAMSITE_COOKIE',"None")
DOMAIN = os.getenv("DOMAIN")

# print(SECURE_COOKIE)
# print(SAMSITE_COOKIE)

login_url = urljoin(BASE_AUTH_URL,'api/login') # ลงชื่อเข้าใช้ / POST
register_url = urljoin(BASE_AUTH_URL,"/api/register") # ลงทะเบียน / POST
logout_url = urljoin(BASE_AUTH_URL,'/api/logout') # ออกจากระบบ / POST
user_url = urljoin(BASE_AUTH_URL,'/api/users') # ข้อมูลผู้ใช้งานทั้งหมด / GET
userProfile_url = urljoin(BASE_AUTH_URL,"/api/profile") # ข้อมูลผู้ใช้งานปัจจุบัน / GET

refresh_token_age = 7 # day
auth_token_age = 7 # day
access_token_age = 30 # minutes


class LoginAPIView(APIView):

    def post(self, request, *args, **kwargs):

        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data.get('refresh')
        access_token = serializer.validated_data.get('access')
        user_data = serializer.validated_data.get('user_data')
        auth_token = serializer.validated_data.get('auth_token')
        authStatus = serializer.validated_data.get('status')
        message = serializer.validated_data.get('message')
        expires_in = serializer.validated_data.get('expires_in')

        # print("refresh_token",refresh_token)
        # print("access_token",access_token)
        # print("user_data",user_data)
        # print("auth_token",auth_token)

        if authStatus == False:
            data = {
                "status" : authStatus,
                "message" : message,
            }
            response = Response(data,status=status.HTTP_200_OK)
            return response

        response = Response(status=status.HTTP_200_OK)
        response.set_cookie( 
            key='refreshtoken',
            value=refresh_token,
            httponly=True, # Production : True
            secure=SECURE_COOKIE , # Production : True
            samesite=SAMSITE_COOKIE, # Production : "None" , Dev : "Lax", "Strict"
            max_age=timedelta(days = refresh_token_age ).total_seconds(),
            # max_age=604800, # <--- กำหนดอายุ 7 วัน (7*24*60*60 วินาที)
            path='/',
            domain=DOMAIN
        )
        response.set_cookie( 
            key=API_AUTH_TOKEN,
            value=auth_token,
            httponly=True, # Production : True
            secure=SECURE_COOKIE, # Production : True
            samesite=SAMSITE_COOKIE, # Production : "None" , Dev : "Lax", "Strict"
            max_age=timedelta(days = auth_token_age ).total_seconds(),
            # max_age=604800, # <--- กำหนดอายุ 7 วัน (7*24*60*60 วินาที)
            path='/',
            domain=DOMAIN
        )
        response.set_cookie( 
            key="access_token",
            value=access_token,
            httponly=True, # Production : True
            secure=SECURE_COOKIE, # Production : True
            samesite=SAMSITE_COOKIE, # Production : "None" , Dev : "Lax", "Strict"
            max_age=timedelta(minutes= access_token_age ).total_seconds(),
            # max_age=604800, # <--- กำหนดอายุ 7 วัน (7*24*60*60 วินาที)
            path='/',
            domain=DOMAIN
        )
        # ส่ง Access Token และ User Data กลับไปใน JSON Body
        response.data = {
            'token' :{
                'access_token': access_token,
                'expires_in':expires_in
            },
            'user_data': user_data,
            'status': authStatus,
        }

        return response


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
        # refresh_token = response.json()["access_token"]
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
        auth_token = request.COOKIES.get(API_AUTH_TOKEN)
        if not auth_token:
            return {"error": "Authorization token required"}, status.HTTP_401_UNAUTHORIZED

        headers = {
            "Authorization": f"Bearer {auth_token}",
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
            key='refreshtoken',
            # path='/',
            samesite="None",
        )
        response.delete_cookie(
            key='auth_token',
            # path='/',
            samesite="None",
        )
        response.delete_cookie(
            key='access_token',
            # path='/',
            samesite="None",
        )
        return response
        

class UsersAPIView(APIView):
    def get(self,request):
        auth_token = request.COOKIES.get(API_AUTH_TOKEN)
        if not auth_token:
            return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.get(user_url,headers=headers)
            response.raise_for_status()
            if response.status_code == 401:
                return response.json()
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

        auth_token = request.COOKIES.get(API_AUTH_TOKEN)
        if not auth_token:
            return Response({'error':'Token not Provided'},status=status.HTTP_401_UNAUTHORIZED)
        try:
            headers={
                "Authorization":f"Bearer {auth_token}",
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

        auth_token = request.COOKIES.get(API_AUTH_TOKEN)
        if not auth_token:
            return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)

        headers={
            "Authorization":f"Bearer {auth_token}",
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
        
        auth_token = request.COOKIES.get(API_AUTH_TOKEN)
        if not auth_token:
            return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)


        headers={
            "Authorization":f"Bearer {auth_token}",
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
        auth_token = request.COOKIES.get(API_AUTH_TOKEN)
        if not auth_token:
            return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)


        headers = {
            "Authorization":f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }

        try:
            # เรียก API ภายนอกเพื่อลบ user
            response = requests.delete(userId_url, headers=headers)
            response.raise_for_status()
            return Response(response.json(), status=status.HTTP_200_OK)
        
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

class TokenRefreshView(APIView):
    def post(self, request):
        refreshtoken = request.COOKIES.get('refreshtoken')

        if not refreshtoken:
            return Response({"detail":"Refresh Token not Found in Cookies"},status=status.HTTP_401_UNAUTHORIZED )
        
        try:
            token = RefreshToken(refreshtoken)
            access_token = str( token.access_token )
            response = Response({"detail": "Token refreshed"})
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                samesite="None",
                secure=True,
                path="/",
                max_age=timedelta(days = access_token_age ).total_seconds(),
                domain=DOMAIN
            )

            return response
        except Exception :
            return Response({"detail":"Token is invalid or Expired" }, status=status.HTTP_401_UNAUTHORIZED)


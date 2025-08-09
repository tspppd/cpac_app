from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
import os
from dotenv import load_dotenv
from urllib.parse import urljoin
import logging
# from serializers import UserUpdateSerializer

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

        return Response(auth_response, status=status.HTTP_200_OK)

    def auth_login(self, username, password):
        headers = {
            "Authorization": f"Bearer {AUTH_PRIVATE_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "username": username,
            "password": password
        }
        try:
            response = requests.post( login_url , headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {'error': 'Authentication failed', 'details': str(e)}


class RegisterAPIView(APIView):
    def post(self, request):
        if not request.data:
            return Response({'error': 'Invalid Data'}, status=status.HTTP_400_BAD_REQUEST)
        
        auth_response = self.auth_register(request)

        # ถ้ามี error ให้ส่ง status 400
        if auth_response.get("error"):
            return Response(auth_response, status=status.HTTP_400_BAD_REQUEST)

        return Response(auth_response, status=status.HTTP_200_OK)
    
    
    def auth_register(self, request):
        token = request.headers.get('Authorization')
        if not token:
            return {"error": "Token not provided"}

        headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }
        logger = logging.getLogger(__name__)

        try:
            data = request.data.copy()
        except Exception as e:
            logger.error(f"Error processing request data: {str(e)}")
            return {"error": "Invalid data format"}

        try:
            response = requests.post(register_url, headers=headers, json=data)
            logger.info(f"Auth server responded: {response.status_code} - {response.text}")
            
            # ถ้าไม่ใช่ 2xx ดึงข้อความ error กลับไปเป็น dict
            if not response.ok:
                return {
                    "error": "Auth server returned error",
                    "status_code": response.status_code,
                    "server_message": response.text
                }
            
            # ถ้าเป็น JSON ให้ parse กลับไป
            return response.json()

        except requests.RequestException as e:
            error_detail = None
            if hasattr(e, 'response') and e.response is not None:
                error_detail = e.response.text
            return {
                "error": "Request to auth server failed",
                "details": str(e),
                "server_message": error_detail
            }



class LogoutAPIView(APIView):
    def post(self, request):
        token = request.headers.get("Authorization")
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)
        headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(logout_url, headers=headers)
            response.raise_for_status()
            return Response({"detail": "Logout successful"}, status=status.HTTP_200_OK)
        except requests.RequestException as e:
            # ดึงรายละเอียดจาก e.response ถ้ามี
            error_detail = None
            if hasattr(e, 'response') and e.response is not None:
                error_detail = e.response.text
            return Response({
                "error": "Request to auth server failed",
                "details": str(e),
                "server_message": error_detail
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UsersAPIView(APIView):
    def get(self,request):
        token = request.headers.get('Authorization')
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }

        try:
            response = requests.get(user_url,headers=headers)
            response.raise_for_status()
            users = response.json()
            return Response( users  # ✅ return รายชื่อ user กลับไปด้วย
            , status=status.HTTP_200_OK)
        except requests.RequestException as e:
            return Response({
                "error": "Getusers failed",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfileAPIView(APIView):
    def get(self,request):
        token = request.headers.get("Authorization")

        headers={
            "Authorization":token,
            "Content-Type": "application/json"
        }

        try:
            response = requests.get(userProfile_url, headers=headers)
            response.raise_for_status()
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

        token = request.headers.get("Authorization")
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        headers={
            "Authorization":token,
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
        
        token = request.headers.get("Authorization")
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        headers={
            "Authorization":token,
            "Content-Type":"application/json"
        }
        
        data = request.data
        if not data:
            return Response({"error": "No data provided for update"}, status=status.HTTP_400_BAD_REQUEST)
        
        logger = logging.getLogger(__name__)
        try:
            data = request.data.copy()
            data.pop("password",None)
            data.pop("password_confirmation",None)
        except Exception as e:
            logger.error(f"Error processing request data: {str(e)}")
            return {"error": "Invalid data format"}
        try:
            response = requests.patch(userId_url,headers=headers,json=data)
            if not response.ok:
                return Response({
                    "error": "Failed to update user",
                    "status_code": response.status_code,
                    "server_message": response.text
                }, status=response.status_code)
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
        token = request.headers.get("Authorization")
        if not token:
            return Response({"error": "Token not provided"}, status=status.HTTP_401_UNAUTHORIZED)

        headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }

        try:
            # เรียก API ภายนอกเพื่อลบ user
            response = requests.delete(userId_url, headers=headers)
            response.raise_for_status()
            return Response({"detail": "User deleted successfully"}, status=status.HTTP_200_OK)
        
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

    
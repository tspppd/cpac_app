from django.urls import path
from .views import *

urlpatterns = [
    path('login/', LoginAPIView.as_view(), name='login'),
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('users/', UsersAPIView.as_view(), name='users'),
    path('profile/', UserProfileAPIView.as_view(), name='userprofile'),
    path('user/<int:userId>/', ManageuserAPIView.as_view(), name='manageuser'),

]
from django.urls import path
from .views import *


urlpatterns = [
    path('login/', LoginAPIView.as_view(), name='login'),
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('users/', UsersAPIView.as_view(), name='users'),
    path('profile/', UserProfileAPIView.as_view(), name='userprofile'),
    path('users/<int:userId>/', ManageuserAPIView.as_view(), name='manageuser'),
    path('refresh/', TokenRefreshView.as_view(), name='refreshtoken'),
    path('cronjob/', CronJobView.as_view(), name='cronjob'),

]
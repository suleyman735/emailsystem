from django.urls import path,include,re_path
from .views import RegisterView,VerifyEmail

# from rest_framework_simplejwt.views import (
#     TokenObtainPairView,
#     TokenRefreshView,
#     TokenVerifyView
# )

urlpatterns = [
   
    path('register/',RegisterView.as_view(), name='register'),
     path('email-verify/',VerifyEmail.as_view(), name='email-verify'),

 
    
]
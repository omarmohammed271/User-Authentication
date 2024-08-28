from django.contrib.auth.tokens import default_token_generator
from rest_framework.authtoken.models import Token
from rest_framework import status
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.decorators import APIView
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings
from .serializers import LoginSerializer,UserSerializer


User = get_user_model()
# Create your views here.
class LoginAPI(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            token,create = Token.objects.get_or_create(user=user)
            data = {
                'message': 'Login Success',
                'token' : token.key
            }
            return Response(data,status=status.HTTP_200_OK)
        return Response({'error':serializer.errors},status=status.HTTP_400_BAD_REQUEST)

class LogoutAPI(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self,request):
        request.user.auth_token.delete()
        return Response({'Message':'Logout Success'},status=status.HTTP_200_OK)
    

class ChangePasswordAPI(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def put(self, request, *args, **kwargs):
        user = request.user
        data = request.data
        
        if not user.check_password(data.get('old_password')):
            return Response({'message':'Wrong old password'},status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(data.get('new_password'))
        user.save()
        return Response({'message':'Password Changed'},status=status.HTTP_200_OK)
    

class ResendActivationLinkAPI(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error':'Email does not exist'},status=status.HTTP_400_BAD_REQUEST)
        if user.is_active:
            return Response({'error':'Email is Active'},status=status.HTTP_400_BAD_REQUEST)
        current_site =  get_current_site(request)
        mail_subject = 'Activate your Accounts'
        # domain user.pk token ----> is_active
        message = f"Activate your Accounts\n{user.username}\n{current_site}/accounts/activate/{urlsafe_base64_encode(force_bytes(user.pk))}/{default_token_generator.make_token(user=user)}" 
        to_email = user.email
        send_mail(mail_subject,message,settings.EMAIL_HOST_USER,[to_email,])
        return Response({'message':'Message was Sent'},status=status.HTTP_200_OK)

class ActivateAccountAPI(APIView):
    def post(self, request,pk,token):
        user_id = urlsafe_base64_decode(pk).decode()
        user = User.objects.get(id=int(user_id))
        if default_token_generator.check_token(user,token):
            user.is_active=True
            user.save()
            return Response({'message':'User is activated'},status=status.HTTP_400_BAD_REQUEST)  
        return Response({'error':'Invalid activation'},status=status.HTTP_400_BAD_REQUEST)

class PasswordResetAPI(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            user =User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error':'Email does not exist'},status=status.HTTP_400_BAD_REQUEST)

        current_site =  get_current_site(request)
        mail_subject = 'Reset your Password'
        # domain user.pk token ----> is_active
        message = f"Reset your Password\n{user.username}\n{current_site}/accounts/reset-password-done/{urlsafe_base64_encode(force_bytes(user.pk))}/{default_token_generator.make_token(user=user)}" 
        to_email = user.email
        send_mail(mail_subject,message,settings.EMAIL_HOST_USER,[to_email,])
        return Response({'message':'Reset Password Link was Sent check your Email'},status=status.HTTP_200_OK)

class PasswordResetDoneAPI(APIView):
    def post(self, request,pk,token ,*args, **kwargs):
        user_id = urlsafe_base64_decode(pk).decode()
        new_password = request.data.get('new_password')
        try:
            user=User.objects.get(id=int(user_id))
        except User.DoesNotExist:
            return Response({'error':'Email does not exist'},status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user,token):
            user.set_password(new_password)
            user.save()
            return Response({'message':'Password Changed Successfully'},status=status.HTTP_200_OK)
        return Response({'error':'Invaid Token'},status=status.HTTP_400_BAD_REQUEST)

class SignupAPI(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = False
            user.save()
            
        current_site =  get_current_site(request)
        mail_subject = 'Activate your Accounts'
        # domain user.pk token ----> is_active
        message = f"Activate your Accounts\n{user.username}\n{current_site}/accounts/activate/{urlsafe_base64_encode(force_bytes(user.pk))}/{default_token_generator.make_token(user=user)}" 
        to_email = user.email
        send_mail(mail_subject,message,settings.EMAIL_HOST_USER,[to_email,])
        return Response({'message':'Message was Sent'},status=status.HTTP_200_OK)
    


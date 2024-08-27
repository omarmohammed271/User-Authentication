from django.contrib.auth.tokens import default_token_generator
from rest_framework.authtoken.models import Token
from rest_framework import status
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.decorators import APIView

from .serializers import LoginSerializer,UserSerializer

# Create your views here.
class LoginAPI(APIView):
    pass

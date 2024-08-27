from django.contrib.auth import authenticate,get_user_model
from rest_framework import serializers

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','username','email','first_name','last_name','password']
        extra_kwargs = {'password':{'write_only':True}}

    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password()
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        user = authenticate(username=attrs['username'],password=attrs['password'])
        if user is None:
            raise serializers.ValidationError('Invalid Username or Password') 
        return user
      
# class PasswordResetSerializer(serializers.Serializer):
#     email = serializers.EmailField()

#     def validate_email(self,value):
#         if not User.objects.filter(email=value).exists():
#             raise serializers.ValidationError('No user Has this Email')
#         return value
    

# class ResetNewPasswordSerializer(serializers.Serializer):
#     password=serializers.CharField()
#     token = serializers.CharField()
#     email = serializers.EmailField()    


from rest_framework import serializers
from .models import User, Student, Teacher, Role, User_Roles, Course
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_str, smart_bytes
from django.urls import reverse
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class StudentRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=15, min_length=8, write_only=True)
    confirmPassword = serializers.CharField(max_length=15, min_length=8, write_only=True)
    level = serializers.CharField(max_length=30, required=True)
    institution = serializers.CharField(max_length=100, required=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirmPassword', 'username', 'level', 'institution']

    def validate(self, attrs):
        password1 = attrs.get('password')
        password2 = attrs.get('confirmPassword')
        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username'], 
            password=validated_data['password']
        )
        user.save()

        student = Student.objects.create(
            user=user,
            level=validated_data['level'],
            institution=validated_data['institution']
        )
        role = Role.objects.get_or_create(name='student')[0]
        user_role = User_Roles.objects.create(user=user, role=role)
        return user

class TeacherRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=15, min_length=8, write_only=True)
    confirmPassword = serializers.CharField(max_length=15, min_length=8, write_only=True)
    institution = serializers.CharField(max_length=100, required=False)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirmPassword', 'username', 'institution']

    def validate(self, attrs):
        password1 = attrs.get('password')
        password2 = attrs.get('confirmPassword')
        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username'], 
            password=validated_data['password']
        )
        user.save()

        teacher = Teacher.objects.create(
            user=user,
            institution=validated_data['institution']
        )
        role = Role.objects.get_or_create(name='teacher')[0]
        user_role = User_Roles.objects.create(user=user, role=role)
        return user
    
class SpecialistRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=15, min_length=8, write_only=True)
    confirmPassword = serializers.CharField(max_length=15, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirmPassword', 'username']

    def validate(self, attrs):
        password1 = attrs.get('password')
        password2 = attrs.get('confirmPassword')
        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        user = User.objects.create_superuser(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username'], 
            password=validated_data['password']
        )
        user.save()
        role = Role.objects.get_or_create(name='specialist')[0]
        user_role = User_Roles.objects.create(user=user, role=role)
        return user  
    
class AdminRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=15, min_length=8, write_only=True)
    confirmPassword = serializers.CharField(max_length=15, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirmPassword', 'username']

    def validate(self, attrs):
        password1 = attrs.get('password')
        password2 = attrs.get('confirmPassword')
        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        user = User.objects.create_superuser(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username'], 
            password=validated_data['password']
        )
        user.save()
        role = Role.objects.get_or_create(name='admin')[0]
        user_role = User_Roles.objects.create(user=user, role=role)
        return user    

class LoginSerializer(serializers.ModelSerializer):
    username=serializers.CharField(max_length=100, write_only=True)
    password=serializers.CharField(max_length=70, write_only=True)    
    full_name=serializers.CharField(max_length=70, read_only=True)    
    access_token=serializers.CharField(max_length=255, read_only=True)    
    refresh_token=serializers.CharField(max_length=255, read_only=True)    

    class Meta:
        model=User
        fields=['username', 'password', 'full_name', 'access_token', 'refresh_token']

    def validate(self, attrs):
        username=attrs.get('username')
        password=attrs.get('password')
        request=self.context.get('request')
        user=authenticate(request, username=username, password=password)
        if not user:
            raise AuthenticationFailed('invalid credentials try again')
        if not user.is_verified:
            raise AuthenticationFailed('email is not verified')

        user_token=user.tokens()
        return {
            'username': user.username,
            'full_name': user.get_full_name(),
            'access_token': str(user_token.get('access')),
            'refresh_token': str(user_token.get('refresh'))
        }
    




class ManageCourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ['title', 'description', 'topic', 'difficulty', 'image_path']

    def create(self, validated_data):
        course = Course.objects.create(**validated_data)
        return course 










class PasswordResetRequestSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255, min_length=6)

    class Meta:
        fields=['email']

    def validate(self, attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uidb64=urlsafe_base64_encode(smart_bytes(user.id))
            token=PasswordResetTokenGenerator().make_token(user)
            request=self.context.get("request")
            site_domain=get_current_site(request).domain
            relative_link=reverse('reset_password_confirm', kwargs={'uidb64':uidb64, 'token':token})
            abslink=f"http://{site_domain} {relative_link}"
            email_body='Hello \n use the link below to reset your password \n' + abslink
            data={
                'email subject':'Password Reset',
                'email_body':email_body,
                'to_email':user.email
            }
            send_normal_email(data)
        return super().validate(attrs)
    
    
class SetNewPasswordSerializer(serializers.Serializer):  
    password=serializers.CharField(max_length=70, min_length=8, write_only=True)
    confirm_password=serializers.CharField(max_length=70, min_length=8, write_only=True)
    uidb64=serializers.CharField(write_only=True)
    token=serializers.CharField(write_only=True)

    class Meta:
        fields=['password', 'confirm_password', 'uidb64', 'token']

    def validate(self, attrs):
        try:
            token=attrs.get('token')
            uidb64=attrs.get('uidb64')
            password=attrs.get('password')
            confirm_password=attrs.get('confirm_password')

            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            if password != confirm_password:
                raise AuthenticationFailed('Password do not match')
            user.set_password(confirm_password)
            user.save()
            return user 
        except Exception:
            return AuthenticationFailed('The reset link is invalid', 401)    
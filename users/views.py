from rest_framework.generics import GenericAPIView
from .serializers import StudentRegisterSerializer, TeacherRegisterSerializer, SpecialistRegisterSerializer, AdminRegisterSerializer, LoginSerializer, ManageCourseSerializer, PasswordResetRequestSerializer, SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .utils import send_code
from .models import OneTimePassword, User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Create your views here.
class RegisterStudentView(GenericAPIView):
    serializer_class=StudentRegisterSerializer
    def post(self, request):
        serializer=self.serializer_class(data=request.data)  
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            student=serializer.data
            send_code(student['email'])
            return Response({
                'data': student,
                'level': serializer.validated_data.get('level'), 
                'institution': serializer.validated_data.get('institution')
            }, status=status.HTTP_201_CREATED) 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterTeacherView(GenericAPIView):
    serializer_class=TeacherRegisterSerializer
    def post(self, request):
        serializer=self.serializer_class(data=request.data)  
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            teacher=serializer.data
            send_code(teacher['email'])
            return Response({
                'data': teacher, 
                'institution': serializer.validated_data.get('institution')
            }, status=status.HTTP_201_CREATED) 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    


class RegisterSpecialistView(GenericAPIView):
    serializer_class=SpecialistRegisterSerializer
    def post(self, request):
        serializer=self.serializer_class(data=request.data)  
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            specialist=serializer.data
            return Response({
                'data': specialist
            }, status=status.HTTP_201_CREATED) 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 


class RegisterAdminView(GenericAPIView):
    serializer_class=AdminRegisterSerializer
    def post(self, request):
        serializer=self.serializer_class(data=request.data)  
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            admin=serializer.data
            return Response({
                'data': admin
            }, status=status.HTTP_201_CREATED) 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)             


class VerifiyUserEmail(GenericAPIView):
    def post(self, request):
        otpcode=request.data.get('otp')
        try:
            user_code_obj=OneTimePassword.objects.get(code=otpcode)
            user=user_code_obj.user
            if not user.is_verified :
                user.is_verified=True
                user.save()
                user_tokens=user.tokens()
                return Response({
                    'message': 'account email verified successfully',
                    'username': user.username,
                    'full_name':user.get_full_name(),
                    'access_token': str(user_tokens.get('access')),
                    'refresh_token': str(user_tokens.get('refresh'))
                }, status=status.HTTP_200_OK)
            return Response({
                'message': 'user already verified'
            }, status=status.HTTP_204_NO_CONTENT)
        except OneTimePassword.DoesNotExist:
            return Response({'message': 'passcode not provided'}, status=status.HTTP_404)
        

class LoginUserView(GenericAPIView):
    serializer_class=LoginSerializer

    def post(self, request):
        serializer=self.serializer_class(data=request.data, context={'request':request})  
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)   

# class TestAuthentication(GenericAPIView):
#     permission_classes=[IsAuthenticated]
#     def get(self, request):
#         return Response({
#             'message': 'success'
#         }, status=status.HTTP_200_OK)


class ManageCourseView(GenericAPIView):
    serializer_class=ManageCourseSerializer

    def post(self, request):
        course_data=request.data
        serializer=self.serializer_class(data=course_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            course=serializer.data
            return Response({
                'data': course,
            }, status=status.HTTP_201_CREATED) 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
    def get(self, request):
        pass




class PasswordResetRequestView(GenericAPIView):
    serializer_class=PasswordResetRequestSerializer
    def post(self, request):
        serializer=self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response({
            'message': 'a link has been sent to your email to reset your password'
        }, status=status.HTTP_200_OK)   


class PasswordResetConfirmView(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id=smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message': 'token is invalid'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({
                'seccess': True,
                'message': 'credentials is valid',
                'token': token, 
                'uidb64': uidb64
            }, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            return Response({'message': 'token is invalid'}, status=status.HTTP_401_UNAUTHORIZED)
        


class SetNewPasswordView(GenericAPIView):
    serializer_class=SetNewPasswordSerializer  
    def patch(self, request):
        serializer=self.serializer_class(data=request.data)      
        serializer.is_valid(raise_exception=True)
        return Response({'message':'password reset success'}, status=status.HTTP_200_OK)     
    




  
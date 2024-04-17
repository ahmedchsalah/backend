from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from .managers import UserManager
from rest_framework_simplejwt.tokens import RefreshToken
# import jwt, datetime

# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
    email=models.EmailField(max_length=100, unique=True, verbose_name=_('Email Address'))
    first_name=models.CharField(max_length=100, verbose_name=_('First Name'))
    last_name=models.CharField(max_length=100, verbose_name=_('Last Name'))
    username=models.CharField(max_length=100, unique=True, null=True, verbose_name=_('Username'))
    is_staff=models.BooleanField(default=False)
    is_superuser=models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    is_active=models.BooleanField(default=True)
    date_joined=models.DateTimeField(auto_now_add=True)
    last_login=models.DateTimeField(auto_now=True)

    USERNAME_FIELD='username'
    REQUIRED_FIELDS=['first_name', 'last_name']

    objects=UserManager()

    def __str__(self):
        return self.email
    
    def get_full_name(self):
        return str(f"{self.first_name} {self.last_name}")
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }


class Student(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    level=models.CharField(max_length=100, null=True, verbose_name=_('Level'))
    institution=models.CharField(max_length=100, null=True, verbose_name=_('Institution'))


class Teacher(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    course=models.CharField(max_length=100, null=True, verbose_name=_('Course'))
    institution=models.CharField(max_length=100, null=True, verbose_name=_('Institution'))    


class Role(models.Model):
    RoleChoices=(
        ('student', 'STUDENT'),
        ('teacher', 'TEACHER'),
        ('specialist','SPECIALIST'),
        ('admin','ADMIN')
    )
    name = models.CharField(max_length=50, choices=RoleChoices)


class User_Roles(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)  


class OneTimePassword(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    code=models.CharField(max_length=6, unique=True)

    def __str__(self):
        return f'{self.user.first_name} passcode'  
    

class Course(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    title=models.CharField(max_length=255, null=True, verbose_name=_('Title'))   
    description=models.CharField(max_length=255, null=True, verbose_name=_('Description')) 
    topic=models.CharField(max_length=50, null=True, verbose_name=_('Topic'))
    difficulty=models.CharField(max_length=50, null=True, verbose_name=_('Difficulty'))
    image_path=models.CharField(max_length=255, null=True, verbose_name=_('Image'))

    def __str__(self):
        return self.title
    

class Feedback(models.Model):
    student=models.OneToOneField(Student, on_delete=models.CASCADE)    
    course=models.OneToOneField(Course, on_delete=models.CASCADE)
    comment=models.CharField(max_length=255, null=True, verbose_name=_('Comment'))
    rating=models.IntegerField(null=True, verbose_name=_('Rating'))


class Lesson(models.Model):
    course=models.OneToOneField(Course, on_delete=models.CASCADE)
    title=models.CharField(max_length=100, null=True, verbose_name=_('Title'))
    content_path=models.CharField(max_length=255, null=True, verbose_name=_('Content_Path'))


class Game(models.Model):
    course=models.OneToOneField(Course, on_delete=models.CASCADE)
    title=models.CharField(max_length=100, null=True, verbose_name=_('Title'))
    game_path=models.CharField(max_length=255, null=True, verbose_name=_('Game_Path'))


class Score(models.Model):
    student=models.OneToOneField(Student, on_delete=models.CASCADE)
    game=models.OneToOneField(Game, on_delete=models.CASCADE)
    XP=models.IntegerField(null=True, verbose_name=_('XP'))   

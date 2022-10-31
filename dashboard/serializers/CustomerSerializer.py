from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.authtoken.models import Token


class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        fields = ("username", "password")
        model = User

    @staticmethod
    def authenticate(request):
        data = request.data
        username = data["username"]
        password = data["password"]
        try:
            user = User.objects.filter(username=username)
            if user and user.check_password(password):
                login(request, user)
                token, created = Token.objects.get_create(user=user)
                return token.key
            return user.username
        except Exception as e:
            return None


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "password", "email")

    @staticmethod
    def create(validated_data):
        username = validated_data["username"]
        password = validated_data["password"]
        email = validated_data["email"]
        try:
            user = User.objects.create_user(username=username, email=email, is_superuser=False, is_staff=False,
                                            is_active=True)
            user.set_password(password)
            response = {"username": user.username, "email": user.email}
            return response
        except Exception as e:
            return None


class ReadAllCustomers(serializers.ModelSerializer):
    class Meta:
        fields = (
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'is_staff',
            'is_active',
            'date_joined',
            'is_superuser',
            'last_login',
            'groups',
            'user_permissions'
        )
        model = User

    @staticmethod
    def get_all_customers():
        customers = User.objects.all().defer("password")
        if customers:
            return customers
        return None

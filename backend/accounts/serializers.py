from rest_framework import serializers

from .models import User


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, trim_whitespace=True)
    password = serializers.CharField(max_length=256, write_only=True, trim_whitespace=False, style={"input_type": "password"})


class UserSerializer(serializers.ModelSerializer):
    role = serializers.CharField(source="effective_role", read_only=True)

    class Meta:
        model = User
        fields = ["id", "username", "first_name", "last_name", "role"]
        read_only_fields = fields

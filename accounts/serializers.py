from rest_framework import serializers
from .models import UserAccount

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)

    default_error_messages = {
        'firs_name': 'The username should only contain alphanumeric characters'}

    class Meta:
        model = UserAccount
        fields = ['email', 'first_name', 'password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        first_name = attrs.get('first_name', '')

        if not first_name.isalnum():
            raise serializers.ValidationError(
                self.default_error_messages)
        return attrs

    def create(self, validated_data):
        return UserAccount .objects.create_user(**validated_data)
    
class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = UserAccount
        fields = ['token']
    
    

        
        

    
    

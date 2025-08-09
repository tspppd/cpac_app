from rest_framework import serializers

class UserUpdateSerializer(serializers.Serializer):
    username = serializers.CharField(min_lenght=4, required=False)
    password = serializers.CharField(min_lenght=8, required=False)
    password_confirmation = serializers.CharField(min_lenght=8, required=False)
    fullname = serializers.CharField(max_length=100, required=False)
    email = serializers.EmailField(required=False)


    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError("ต้องมีอย่างน้อยหนึ่งฟิลด์ในการแก้ไขข้อมูล")
        return attrs

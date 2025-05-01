"""
"""
from rest_framework import serializers

class EraseBGSerializer(serializers.Serializer):
    """
    
    """
    image = serializers.EraseBGImageField()
    prompt = serializers.CharField(default="Erase the background from the foreground")
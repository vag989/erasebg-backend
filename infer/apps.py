"""
Apps.py for infer
"""

import os

from django.apps import AppConfig

from erasebg.settings import REPLICATE_API_TOKEN

class InferConfig(AppConfig):
    """
    App configuring
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'infer'

    def ready(self):
        os.environ['REPLICATE_API_TOKEN'] = REPLICATE_API_TOKEN

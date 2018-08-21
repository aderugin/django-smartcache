from django.apps import AppConfig
from django.conf import settings
from django.db.models.signals import post_delete, post_save

from .viewcache import (
    change_instance_handler, update_instances_handler, delete_instance_handler, SMART
)
from .signals import post_update, querycache_invalidated


class CacheAppConfig(AppConfig):
    name = 'unegui.cache'
    verbose_name = 'Cache'

    def ready(self):
        if settings.VIEWCACHE_ENABLED and SMART:
            post_update.connect(update_instances_handler)
            post_save.connect(change_instance_handler)
            querycache_invalidated.connect(update_instances_handler)

from django.dispatch import Signal

post_update = Signal(providing_args=['pk_list'])
querycache_invalidated = Signal(providing_args=['pk_list'])

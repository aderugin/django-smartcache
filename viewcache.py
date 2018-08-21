import pickle

from collections import defaultdict

from django.conf import settings
from django.db import models

from .utils import (
    get_view_name, get_model_name, get_request_cache_key, format_key, redis_client, DAY
)

registred_views = []


CACHE_PREFIX = 'viewcache'

TAGS_PREFIX = format_key(CACHE_PREFIX, 'viewtags')

ALLTAGS_PREFIX = format_key(CACHE_PREFIX, 'alltags')

VERSIONS_PREFIX = format_key(CACHE_PREFIX, 'versions')

VIEWS_PREFIX = format_key(CACHE_PREFIX, 'views')

# VIEWNAMES_PREFIX = format_key(CACHE_PREFIX, 'viewnames')

ALLTAGS_TIMEOUT = DAY * 2

INCLUDE_INVALIDATION_MODELS = getattr(settings, 'VIEWCACHE_INCLUDE_INVALIDATION_MODELS', [])

EXCLUDE_INVALIDATION_MODELS = getattr(settings, 'VIEWCACHE_EXCLUDE_INVALIDATION_MODELS', [])

SMART = getattr(settings, 'VIEWCACHE_SMART', True)

# Redis keys
# 'viewscache:versions:<tag> <version>'
# 'viewscache:alltags {<tag>:<version>}'
# 'viewscache:viewtags:<hash> {<tag>:<version>}'
# 'viewscache:viewnames:<name> {<key>}


def cached_view(timeout=60 * 60, cache_ajax=True, private=False, smart_invalidation=SMART,
                signal=None, context_objects=None, exclude=None, exclude_staff=False,
                exclude_authenticated=False):
    """
    Кеширование на уровне представления
    @param cache_ajax - кешировать ajax запросы
    @param private – персонально для пользователя
    @param smart_invalidation - инвалидация на основе объектов в контексте
    @param signal - сигнал создании объекта (приводит к ленивой инвалидации)
    @param context_objects - func(context) -> {<model_name>: {<pk>}}
    @param exclude - func(request) -> bool
    """
    context_objects = context_objects or (lambda context: {})
    exclude = exclude or (lambda request: False)
    assert callable(context_objects)
    assert callable(exclude)

    if settings.VIEWCACHE_ENABLED and signal:
        signal.connect(invalidate_model_handler)

    def decorator(cls):
        if cls not in registred_views:
            registred_views.append(cls)

        origin_dispatch = cls.dispatch

        def dispatch(self, request, *args, **kwargs):
            if is_cache_denied(request):
                return origin_dispatch(self, request, *args, **kwargs)
            cache_key = format_key(
                VIEWS_PREFIX,
                get_view_name(cls),
                get_request_cache_key(request, private)
            )
            response = load_response(cache_key)
            if response is None:
                response = origin_dispatch(self, request, *args, **kwargs)
                if hasattr(response, 'render'):
                    response.add_post_render_callback(lambda r: cache_response(cache_key, r))
                else:
                    cache_response(cache_key, response)
            return response

        if settings.VIEWCACHE_ENABLED:
            cls.dispatch = dispatch
        return cls

    def is_cache_denied(request):
        return any([
            exclude(request),
            request.method != 'GET',
            not cache_ajax and request.is_ajax(),
            exclude_authenticated and request.user.is_authenticated,
            (
                exclude_staff and
                request.user.is_authenticated and
                (request.user.is_staff or request.user.is_moderator)
            )
        ])

    def load_response(cache_key):
        if smart_invalidation and redis_client.sdiff([format_key(TAGS_PREFIX, cache_key), ALLTAGS_PREFIX]):
            return None
        try:
            return pickle.loads(redis_client.get(cache_key))
        except Exception:
            return None

    def cache_response(cache_key, response):
        cleanup(cache_key)
        redis_client.set(cache_key, pickle.dumps(response), timeout)
        if smart_invalidation and hasattr(response, 'context_data'):
            set_cache_tags(cache_key, response.context_data)

    def set_cache_tags(cache_key, context):
        context_objects_ids = get_context_objects(context)
        if not context_objects_ids:
            return None

        # 1. Сгенерировать список тегов
        # 2. Получить список версий из списка тегов mget(keys)
        # 3. Сгенерировать список тегов с версиями
        # 4. Записать теги с версиями для view
        # 5. Записать в alltags не достающие теги

        tags = {format_key(n, pk) for n, pks in context_objects_ids.items() for pk in pks}
        tags |= set(context_objects_ids.keys())
        tags = list(tags)
        version_tags = []
        default_tags = []
        versions = dict(zip(tags, redis_client.mget([format_key(VERSIONS_PREFIX, t) for t in tags])))
        for tag, version in versions.items():
            try:
                version_tags.append(format_key(tag, 'v%s' % int(version)))
            except (TypeError, ValueError):
                vtag = format_key(tag, 'v0')
                version_tags.append(vtag)
                default_tags.append(vtag)

        cache_key_tags = format_key(TAGS_PREFIX, cache_key)
        redis_client.delete(cache_key_tags)
        redis_client.sadd(cache_key_tags, *version_tags)
        redis_client.expire(cache_key_tags, timeout)
        if default_tags:
            created = not redis_client.exists(ALLTAGS_PREFIX)
            redis_client.sadd(ALLTAGS_PREFIX, *default_tags)
            if created:
                redis_client.expire(ALLTAGS_PREFIX, ALLTAGS_TIMEOUT)

    def cleanup(cache_key):
        redis_client.delete(
            '%s:%s' % (VIEWS_PREFIX, cache_key),
            '%s:%s' % (TAGS_PREFIX, cache_key)
        )

    def get_context_objects(context):
        context_objects_ids = defaultdict(set)
        for item in context.values():
            if isinstance(item, models.Model):
                context_objects_ids[get_model_name(item)].add(item.pk)
            if isinstance(item, models.QuerySet):
                context_objects_ids[get_model_name(item.model)] |= {o.pk for o in item}
            if item and isinstance(item, (list, tuple)) and isinstance(item[0], models.Model):
                for obj in item:
                    if isinstance(obj, models.Model):
                        context_objects_ids[get_model_name(obj)].add(obj.pk)
        for model, pks in context_objects(context).items():
            if issubclass(model, models.Model):
                model = get_model_name(model)
            context_objects_ids[model] |= set(pks)
        return dict(context_objects_ids)

    # TODO: оптимизация
    # def save_viewname(name):
    #     key = format_key(VIEWNAMES_PREFIX, name)
    #     created = redis_client.exists(key)
    #     redis_client.sadd(VIEWNAMES_PREFIX, cache_key)
    #     if created:
    #         redis_client.expire(key, 60 * 60 * 24)
    return decorator


def invalidate_model_handler(sender, **kwargs):
    update_tag_version(get_model_name(sender))


def change_instance_handler(sender, **kwargs):
    if not is_allowed_signal_sender(sender):
        return None
    instance = kwargs.pop('instance', None)
    if instance is None:
        tag = get_model_name(sender)
    else:
        tag = get_instance_tag(instance)
    update_tag_version(tag)


def delete_instance_handler(sender, instance, **kwargs):
    if not is_allowed_signal_sender(sender):
        return None
    redis_client.delete(format_key(VERSIONS_PREFIX, instance.pk))
    tags = list(redis_client.sscan_iter(ALLTAGS_PREFIX, '%s*' % format_key(get_model_name(sender), instance.pk)))
    if tags:
        redis_client.srem(ALLTAGS_PREFIX, *tags)


def update_instances_handler(sender, pk_list, **kwargs):
    if not is_allowed_signal_sender(sender):
        return None
    invalidate_view_by_pk_list(sender, pk_list)


def invalidate_view_by_instance(instance):
    update_tag_version(get_instance_tag(instance))


def invalidate_view_by_pk_list(model, pk_list):
    if not pk_list:
        return None
    tags = [format_key(get_model_name(model), pk) for pk in pk_list]
    versions = dict(zip(tags, redis_client.mget([format_key(VERSIONS_PREFIX, t) for t in tags])))
    for tag, version in versions.items():
        try:
            version = int(version)
        except (TypeError, ValueError):
            version = 0

        def callback(pipe):
            pipe.multi()
            pipe.srem(ALLTAGS_PREFIX, '%s:v%s' % (tag, version))
            # pipe.sadd(ALLTAGS_PREFIX, '%s:v%s' % (tag, redis_client.incr(format_key(VERSIONS_PREFIX, tag))))
            pipe.sadd(ALLTAGS_PREFIX, '%s:v%s' % (tag, version + 1))
            pipe.set(format_key(VERSIONS_PREFIX, tag), version + 1, ALLTAGS_TIMEOUT)

        created = not redis_client.exists(ALLTAGS_PREFIX)
        redis_client.transaction(callback)
        if created:
            redis_client.expire(ALLTAGS_PREFIX, ALLTAGS_TIMEOUT)


def invalidate_view_by_name(view_name=None):
    if view_name:
        view_name = view_name.lower()
        keys = list(redis_client.scan_iter(match='%s:%s*' % (VIEWS_PREFIX, view_name)))
        keys += list(redis_client.scan_iter(match='%s:%s*' % (TAGS_PREFIX, view_name)))
    else:
        keys = list(redis_client.scan_iter(match='%s*' % CACHE_PREFIX))
    if keys:
        redis_client.delete(*keys)


def get_instance_tag(instance):
    return '%s:%s' % (get_model_name(instance), instance.pk)


def update_tag_version(tag):
    version_key = format_key(VERSIONS_PREFIX, tag)

    def callback(pipe):
        try:
            version = int(redis_client.get(version_key))
        except (TypeError, ValueError):
            version = 0
        pipe.multi()
        pipe.srem(ALLTAGS_PREFIX, '%s:v%s' % (tag, version))
        pipe.sadd(ALLTAGS_PREFIX, '%s:v%s' % (tag, version + 1))
        pipe.set(version_key, version + 1, ALLTAGS_TIMEOUT)

    created = not redis_client.exists(ALLTAGS_PREFIX)
    redis_client.transaction(callback, version_key)
    if created:
        redis_client.expire(ALLTAGS_PREFIX, ALLTAGS_TIMEOUT)


def is_allowed_signal_sender(sender):
    model_name = get_model_name(sender)
    if INCLUDE_INVALIDATION_MODELS:
        return model_name in [m.lower() for m in INCLUDE_INVALIDATION_MODELS]
    return model_name not in [m.lower() for m in EXCLUDE_INVALIDATION_MODELS]

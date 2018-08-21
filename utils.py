import redis
import pickle
import hashlib
from functools import wraps

from django_mobile import get_flavour
from django.conf import settings
from django.core.cache import cache
from django.utils.encoding import force_bytes, iri_to_uri

COOKIE_KEYS = getattr(settings, 'VIEWCACHE_COOKIE_KEYS', ())

MINUTE = 60

HOUR = MINUTE * 60

DAY = HOUR * 24

redis_client = redis.StrictRedis.from_url(settings.QUERYCACHE_REDIS)

try:
    redis_client.time()
except redis.ConnectionError:
    redis_client = cache.get_client('default')


def get_model_name(model):
    return ('%s.%s' % (model._meta.app_label, model._meta.model_name)).lower()


def get_view_name(view):
    return ('%s.%s' % (view.__module__, view.__name__)).lower()


def format_key(*args):
    return ':'.join([str(arg) for arg in args])


def safe_pickle_load(value, default=None):
    try:
        return pickle.loads(value)
    except Exception:
        return default


def stamp_model_fields(model):
    return str(sorted((f.name, f.attname, f.db_column, f.__class__) for f in model._meta.fields)).encode()


def get_request_cache_key(request, private=False):
    """
    Уникальный ключ для request
    @param private - уникальный ключ для каждого пользователя
    """
    md5 = hashlib.md5()
    md5.update(force_bytes(iri_to_uri(_get_full_path(request))))
    md5.update(force_bytes(_get_cookie_key(request, private)))
    md5.update(force_bytes(get_flavour(request)))
    if request.is_ajax():
        md5.update(force_bytes('ajax'))
    return md5.hexdigest()


def _get_full_path(request):
    query_string = []
    for key in sorted(request.GET.keys()):
        if key == '_':
            continue
        for value in request.GET.getlist(key):
            query_string.append('%s=%s' % (key, value))
    query_string = '&'.join(query_string)
    if not query_string:
        return request.path
    return '%s?%s' % (request.path, query_string)


def _get_cookie_key(request, private=False):
    keys = COOKIE_KEYS
    if private:
        keys += ('sessionid',)
    return '_'.join(['%s_%s' % (k, request.COOKIES.get(k, '')) for k in COOKIE_KEYS])


def cached_model_invalidation(model):
    """
    Декоратор для класса
    Добавляет методы инвалидации модели
    instance.invalidate_cache() - инвалидирует все cached_model_method на уровне instance
    Model.invalidate_all_cache() - инвалидирует все cached_model_method на уровне класса
    """
    def invalidate_all_cache(cls):
        for method in cls._cached_method:
            cache.delete_pattern('%s*' % method._get_cache_key(cls)[0])
    invalidate_all_cache = classmethod(invalidate_all_cache)

    def invalidate_cache(self):
        for method in self._cached_methods.values():
            method.invalidate(self)

    model.invalidate_cache = invalidate_cache
    model.invalidate_all_cache = invalidate_all_cache
    model._cached_methods = {}
    for name in dir(model):
        attr = getattr(model, name)
        if hasattr(attr, 'invalidate'):
            model._cached_methods[name] = attr
    return model


def cached_model_method(key=None, fields='pk', timeout=60 * 60):
    """
    Кеширует метод модели
    @param key - ключ кеша, если не задан, то генерируется
    @param fields - поля модели для создания специфичной части ключа, если передать None,
        то создасться общий ключ для всех вызовов
    @param timeout - ttl кеша

    instance.<method>.invalidate(instance) - инвалидация метода
    """
    if not isinstance(fields, (list, tuple)):
        fields = [fields] if fields else []

    def decorator(func):
        def get_cache_key(instance):
            cache_key = [key]
            if cache_key[0] is None:
                cache_key[0] = '_'.join([instance._meta.app_label, instance._meta.model_name, func.__name__])
            if fields:
                values = tuple(str(getattr(instance, k)) for k in fields)
                try:
                    cache_key[0] = cache_key[0] % values
                except TypeError:
                    cache_key.append('_'.join(values))
            return cache_key

        def invalidate(instance):
            cache_key = ':'.join(get_cache_key(instance))
            cache.delete_pattern('%s*' % cache_key)

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            cache_key = get_cache_key(self)
            if args or kwargs:
                cache_key.append(hashlib.md5((str(args) + str(kwargs).encode())))
            result = cache.get(':'.join(cache_key))
            if result is None:
                result = func(self, *args, **kwargs)
                cache.set(':'.join(cache_key), result, timeout)
            return result
        wrapper.invalidate = invalidate
        wrapper._get_cache_key = get_cache_key
        return wrapper
    return decorator

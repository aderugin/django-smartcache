import hashlib
import pickle
import json
import itertools

from django.conf import settings
from django.utils.encoding import smart_str, force_bytes
from django.utils.functional import cached_property
from django.db.models.sql.datastructures import EmptyResultSet
from django.db import models
from django.db.models.query import ValuesIterable, ValuesListIterable, FlatValuesListIterable
from django.db.models.signals import post_delete, post_save

from .utils import get_model_name, stamp_model_fields, redis_client, format_key
from .signals import post_update, querycache_invalidated

CACHE_PREFIX = 'querycache'

SHALLOW_CHECK_TIMEOUT = getattr(settings, 'QUERYCACHE_SHALLOW_CHECK_TIMEOUT', 60 * 5)

DEFAULT_SEND_UPDATE_SIGNAL = getattr(settings, 'QUERYCACHE_DEFAULT_SEND_UPDATE_SIGNAL', False)

registred_models = []


class CacheQuerySetMixin(object):
    """
    Кеширование на уровне queryset

    Стратегия хранения данных.
        Queryset разделяется на две части: список pk и hash таблица {<pk>: pickle.dumps(obj)}
        <namespace>:<modelname>:objects:<queryhash> [pk]
        <namespace>:<modelname>:checked:<queryhash> 1
        <namespace>:<modelname>:object:<fieldhash> {pk: obj}
        <namespace>:<modelname>:objects_hashes {pk: [fieldhash]}

    Стратегия инвалидации.
        При удалении или изменении данных, инвалидация происходит сразу,
        по сигналам post_save, post_delete

        Также работает механизм легкой проверки актуальности данных в закешированной выборке
        (он актуален при добавлении данных): делается запрос в БД последнего элемента выборки
        и если его pk не совпадает с последним pk закешированной выборки, то происходит
        инвалидация. Интервал такой проверки задается константой QUERYCACHE_SHALLOW_CHECK_TIMEOUT
    """
    cache_by_default = False
    _use_cache = cache_by_default
    _cache_timeout = None
    _check_timeout = SHALLOW_CHECK_TIMEOUT

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if settings.QUERYCACHE_ENABLED and self.model and self.model not in registred_models:
            registred_models.append(self.model)
            _connect_invalidate_signals(self.model)

    def _fetch_all(self):
        if (self._result_cache is not None or
                not settings.QUERYCACHE_ENABLED or not self._use_cache or self._for_write):
            return super()._fetch_all()
        self._result_cache = self._load_cached_objects()
        if self._should_invalidate():
            self.invalidate()
        if self._result_cache is None:
            self._result_cache = list(self._iterable_class(self))
            self._cache_objects(self._result_cache)
        return super()._fetch_all()

    def _cache_objects(self, objects):
        pk_index = self._get_values_select_pk_index()
        objects_pks = []
        objects_as_dict = {}
        for obj in objects:
            pk = self._get_obj_pk(obj, pk_index)
            if pk is None:
                return None
            objects_as_dict[pk] = pickle.dumps(obj)
            objects_pks.append(pk)
        if not objects_as_dict:
            return None

        redis_client.hmset(self._cache_object_key, objects_as_dict)
        redis_client.set(self._cache_objects_key, json.dumps(objects_pks))
        self._set_checked_mark()

        fields_hash = self._cache_fields_hash
        objects_hashes = dict(zip(
            objects_pks,
            redis_client.hmget(self._cache_objects_hashes_key, objects_pks)
        ))
        for pk in objects_hashes:
            hashes = objects_hashes[pk]
            if hashes is None:
                hashes = []
            else:
                try:
                    hashes = json.loads(hashes.decode())
                except Exception:
                    hashes = []
            if fields_hash not in hashes:
                hashes.append(fields_hash)
            objects_hashes[pk] = json.dumps(hashes)
        redis_client.hmset(self._cache_objects_hashes_key, objects_hashes)
        self._set_expire()

    def _load_cached_objects(self):
        objects_pks = redis_client.get(self._cache_objects_key)
        if objects_pks is None:
            return None
        try:
            objects_pks = json.loads(objects_pks.decode())
        except Exception:
            # Данные испорчены, инвалидируем
            self.invalidate()
            return None
        if not objects_pks:
            return None
        objects = []
        for value in redis_client.hmget(self._cache_object_key, objects_pks):
            if value is None:
                # Если значения не хватает, то ивалидируем
                self.invalidate()
                return None
            obj = pickle.loads(value)
            # Вылетала ошибка ValueError: Cannot assign "<Instance>": the current database router
            # prevents this relation.
            # Связано с особенностью работы репликации django и django.db.utils.ConnectionRouter
            # Выставляем db объекта из queryset
            if isinstance(obj, self.model):
                obj._state.db = self.db
            objects.append(obj)
        return objects

    def _set_expire(self):
        timeout = self._cache_timeout
        if timeout is None:
            timeout = 60 * 60 * 24 * 365
        for key in (self._cache_object_key, self._cache_objects_hashes_key,
                    self._cache_objects_key):
            redis_client.expire(key, timeout)

    def _should_invalidate(self):
        if self._result_cache and not redis_client.exists(self._cache_checked_key):
            pk_index = self._get_values_select_pk_index()
            last_pk = self._get_last_pk()
            if not last_pk or last_pk != self._get_obj_pk(self._result_cache[-1], pk_index):
                return True
            self._set_checked_mark()
        return False

    def _get_obj_pk(self, obj, index=None):
        if isinstance(obj, self.model):
            return obj.pk
        if index is None:
            return None
        if isinstance(obj, dict):
            return obj.get(self.query.values_select[index])
        if isinstance(obj, (tuple, list)):
            return obj[index]
        if isinstance(obj, (int, str)) and index is 0:
            return obj

    def _get_values_select_pk_index(self):
        index = None
        if self._iterable_class in [ValuesIterable, ValuesListIterable, FlatValuesListIterable]:
            for i, field in enumerate(self.query.values_select):
                if field in ('pk', self.model._meta.pk.name):
                    index = i
                    break
        return index

    def _get_last_pk(self):
        queryset = self.nocache().values_list('pk', flat=True)
        if self.query.high_mark is None or self.query.high_mark < 1:
            return queryset.last()
        try:
            return queryset[self.query.high_mark - 1]
        except IndexError:
            return None

    def _set_checked_mark(self):
        redis_client.set(self._cache_checked_key, 1, self._check_timeout)

    @property
    def _cache_checked_key(self):
        return '%s:checked:%s' % (get_cache_prefix(self.model), self._cache_hash)

    @property
    def _cache_object_key(self):
        return '%s:object:%s' % (get_cache_prefix(self.model), self._cache_fields_hash)

    @property
    def _cache_objects_hashes_key(self):
        return '%s:objects_hashes' % get_cache_prefix(self.model)

    @property
    def _cache_objects_key(self):
        return '%s:objects:%s' % (get_cache_prefix(self.model), self._cache_hash)

    @cached_property
    def _cache_hash(self):
        md = hashlib.md5()
        md.update(stamp_model_fields(self.model))
        try:
            sql, params = self.query.get_compiler(self.db).as_sql()
            sql_str = sql % params
            md.update(smart_str(sql_str).encode())
        except EmptyResultSet:
            pass
        return md.hexdigest()

    @property
    def _cache_fields_hash(self):
        md = hashlib.md5()
        md.update(stamp_model_fields(self.model))
        md.update(force_bytes(self._iterable_class.__name__))
        try:
            sql, params = self.query.get_compiler(self.db).as_sql()
            sql_str = sql % params
            sql_str = sql_str.split('FROM')[0].strip()
            md.update(smart_str(sql_str).encode())
        except EmptyResultSet:
            pass
        return md.hexdigest()

    def _chain(self, **kwargs):
        # TODO: new api, _chain()?
        kwargs = {
            '_use_cache': self._use_cache,
            '_cache_timeout': self._cache_timeout,
            '_check_timeout': self._check_timeout,
            **kwargs
        }
        return super()._chain(**kwargs)

    def invalidate(self):
        key = self._cache_objects_key
        try:
            pk_list = json.loads(redis_client.get(key))
        except Exception:
            pk_list = []
        querycache_invalidated.send(sender=self.model, pk_list=pk_list)
        redis_client.delete(key)
        redis_client.delete(self._cache_checked_key)
        self._result_cache = None

    def cache(self, timeout=60 * 60, check_timeout=SHALLOW_CHECK_TIMEOUT):
        if check_timeout is None:
            check_timeout = timeout
        assert check_timeout <= timeout
        return self._chain(_use_cache=True, _cache_timeout=timeout, _check_timeout=check_timeout)

    def nocache(self):
        return self._chain(_use_cache=False)

    def update(self, send_signal=DEFAULT_SEND_UPDATE_SIGNAL, **kwargs):
        if not settings.QUERYCACHE_ENABLED or not send_signal:
            return super().update(**kwargs)
        pk_list = list(self.nocache().values_list('pk', flat=True))
        rows = super().update(**kwargs)
        post_update.send(sender=self.model, pk_list=pk_list)
        return rows


def _connect_invalidate_signals(model):
    for signal in [post_delete, post_save]:
        signal.connect(change_instance_handler, sender=model)
    post_update.connect(update_instances_handler, sender=model)


def change_instance_handler(sender, instance, **kwargs):
    invalidate_instance(instance)


def update_instances_handler(sender, pk_list, **kwargs):
    bulk_invalidate_instances(sender, pk_list)


def invalidate_instance(instance):
    assert isinstance(instance, models.Model)
    hashes_key = '%s:objects_hashes' % get_cache_prefix(instance)
    object_hashes = redis_client.hget(hashes_key, instance.pk)
    if object_hashes is not None:
        object_hashes = json.loads(object_hashes.decode())
    for object_hash in object_hashes or []:
        key = '%s:object:%s' % (get_cache_prefix(instance), object_hash)
        redis_client.hdel(key, instance.pk)
    redis_client.hdel(hashes_key, instance.pk)


def bulk_invalidate_instances(model, pk_list):
    assert issubclass(model, models.Model)
    if not pk_list:
        return None
    hashes_key = '%s:objects_hashes' % get_cache_prefix(model)
    object_hashes = []
    for value in redis_client.hmget(hashes_key, pk_list):
        if value:
            try:
                object_hashes.append(json.loads(value))
            except Exception:
                pass
    object_hashes = itertools.chain.from_iterable(object_hashes)
    for object_hash in object_hashes or []:
        key = '%s:object:%s' % (get_cache_prefix(model), object_hash)
        redis_client.hdel(key, *pk_list)
    redis_client.hdel(hashes_key, *pk_list)


def invalidate_by_model_name(model_name=None):
    prefix = CACHE_PREFIX
    if model_name:
        prefix = format_key(prefix, model_name)
    keys = list(redis_client.scan_iter('%s*' % prefix))
    if keys:
        redis_client.delete(*keys)


def get_cache_prefix(model):
    return format_key(CACHE_PREFIX, get_model_name(model))

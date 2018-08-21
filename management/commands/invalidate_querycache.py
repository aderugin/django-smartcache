from django.core.management.base import BaseCommand
from smartcache.querycache import invalidate_by_model_name


class Command(BaseCommand):
    help = 'Invalidate queryset cache'

    def add_arguments(self, parser):
        parser.add_argument('model_name', nargs='*', type=str)

    def handle(self, *args, **options):
        if options['model_name']:
            for model_name in options['model_name']:
                invalidate_by_model_name(model_name.lower())
                self.stdout.write(self.style.SUCCESS('%s queryset cache has been invalidated' % model_name))
        else:
            invalidate_by_model_name()
            self.stdout.write(self.style.SUCCESS('All queryset cache has been invalidated'))

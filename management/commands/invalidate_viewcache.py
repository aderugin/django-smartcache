from django.core.management.base import BaseCommand
from smartcache.viewcache import invalidate_view_by_name


class Command(BaseCommand):
    help = 'Invalidate view cache'

    def add_arguments(self, parser):
        parser.add_argument('view_name', nargs='*', type=str)

    def handle(self, *args, **options):
        if options['view_name']:
            for view_name in options['view_name']:
                invalidate_view_by_name(view_name.lower())
                self.stdout.write(self.style.SUCCESS('%s view cache has been invalidated' % view_name))
        else:
            invalidate_view_by_name()
            self.stdout.write(self.style.SUCCESS('All view cache has been invalidated'))

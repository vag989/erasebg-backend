export DJANGO_ENV="dev"

echo "DJANGO_ENV set to:" $DJANGO_ENV

echo "Running tests for infer"
python manage.py test infer --keepdb

echo "Running tests for payments"
python manage.py test payments --keepdb

echo "Running tests for users"
python manage.py test users --keepdb

export DJANGO_ENV="production"

echo "DJANGO_ENV set to:" $DJANGO_ENV

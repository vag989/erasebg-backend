OLD_ENV=$DJANGO_ENV

export DJANGO_ENV="local"

echo "DJANGO_ENV set to:" $DJANGO_ENV

echo "Running migrations"
python manage.py makemigrations
python manage.py migrate

echo "Running tests for infer"
python manage.py test infer --keepdb

echo "Running tests for payments"
python manage.py test payments --keepdb

echo "Running tests for users"
python manage.py test users --keepdb

export DJANGO_ENV=$OLD_ENV

echo "DJANGO_ENV set to:" $DJANGO_ENV

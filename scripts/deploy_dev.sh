python manage.py makemigrations
python manage.py migrate
python manage.py collectstatic

sudo systemctl daemon-reload
sudo systemctl restart gunicorn-erasebg-dev.service
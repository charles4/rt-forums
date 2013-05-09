uwsgi --master --socket :3031 --wsgi-file forum.py --callable app --processes 4 --threads 2 --stats 127.0.0.1:9191 --die-on-term --daeomonize /home/charles/logs/uwsgi.log

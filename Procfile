web: gunicorn main:app
git push heroku master
heroku run rake db:migrate
heroku restart
# -*- coding: utf8 -*-

import os
import datetime
from flask import (
    Flask,
    request,
    session,
    g,
    redirect,
    url_for,
    abort,
    render_template,
    flash,
)
from peewee import *
from functools import wraps
from hashlib import md5


# TODO: прочитать PEP8 - там описан стайл-гайд про офомрмление Python-кода: https://www.python.org/dev/peps/pep-0008/
# TODO: прочитать google style guide, там описано то, про что забыли написать в pep8 - https://google.github.io/styleguide/pyguide.html


app = Flask(__name__)  # create the application instance

# FIXME: настройку приложения надо либо вытащить в отдельный файл, либо брать только из словаря, если делать from_object(__name__), в конфиг скопируются все переменные и функции из этого файла
app.config.from_object(__name__)  # load config from this file , tractor.py


# Load default config and override config from an environment variable
app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'tractor.db'),
    SECRET_KEY='development key',
    DEBUG=True
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)


# NOTE: сейчас ок, но вообще не рекомендуется коммитить в репозиотрий большие нетекстовые файлы, в частности базы
# данных, т.к. git хранит всю историю изменений, это приодит к распуханию репозитория и засорению диффов в мердж-реквестах
database = SqliteDatabase('tractor.db') # FIXME: это значение должно браться сиз конфига, чтобы 1) было понятно, где смотреть, к какой БД коннектиться, 2) в случе изменения, менять только в одном месте. Из конфига можно взять так: app.config['DATABASE']


# TODO: вынести классы модели в отдельный файл models.py
class BaseModel(Model):
    class Meta:
        database = database


class User(BaseModel):
    username = CharField(unique=True)
    password = CharField()

    class Meta:
        order_by = ('username',)


class Message(BaseModel):
    user = ForeignKeyField(User)
    pub_date = DateTimeField()
    title = TextField()
    content = TextField()

    class Meta:
        order_by = ('-pub_date',)


# TODO: вынести вспомогательные функции в отдельный файл utils.py
def create_tables():
    database.connect()
    database.create_tables(([User, Message]))


def auth_user(user):
    # TODO: разобраться, почему здесь мы пишем что-то в session и как это работает
    session['logged_in'] = True
    session['user_id'] = user.id
    session['username'] = user.username
    flash('Hello, %s' % (user.username))


def object_list(template_name, qr, var_name='object_list', **kwargs):
    # TODO: вынести кол-во элементов на страницу в параметры функции object_list
    kwargs.update(
        page=int(request.args.get('page', 1)),
        pages=qr.count() / 4 + 1
    )
    kwargs[var_name] = qr.paginate(kwargs['page'], 4)

    return render_template(template_name, **kwargs)


def get_current_user():
    if session.get('logged_in'):
        return User.get(User.id == session['user_id'])


def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return inner


def get_object_or_404(model, *expressions):  # no need
    try:
        return model.get(*expressions)
    except model.DoesNotExist:
        abort(404)


@app.before_request
def before_request():
    g.db = database
    g.db.connect()


@app.after_request
def after_request(response):
    g.db.close()
    return response


# TODO: вынести функции-обработчики запросов в отдельный файл views.py
@app.route('/', methods=['GET', 'POST'])
def start_page():
    usernames = User.select(User.username)
    if request.method == 'POST':
        users = request.form.getlist('users')
        filter = []
        for user in users:
            user = User.get(User.username == user).id
            filter.append(user)
        session['filter'] = filter
        return redirect(url_for('filter'))
    messages = Message.select()
    return object_list('show_messages.html', messages, 'message_list', usernames=usernames)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def create():
    user = get_current_user()
    if request.method == 'POST' and request.form['content']:
        Message.create(
            user=user,
            pub_date=datetime.datetime.now(),
            title=request.form['title'],
            content=request.form['content'])

        # TODO: разобраться, как рабтает функция flash
        flash('Your message has been created')

        # TODO: разобраться, как работает функция redirect
        return redirect(url_for('start_page'))

    return render_template('create.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # TODO: переделать форму авторизации с испольлзованием библиотеки http://wtforms.readthedocs.io/en/latest/
    if request.method == 'POST' and request.form['username']:
        try:
            user = User.get(
                username=request.form['username'],
                password=md5((request.form['password']).encode('utf-8')).hexdigest())
        except User.DoesNotExist:
            flash('The password or username entered is incorrect')
        else:
            auth_user(user)
            return redirect(url_for('start_page'))

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST' and request.form['username']:
        try:
            with database.transaction():
                # Attempt to create the user. If the username is taken, due to the
                # unique constraint, the database will raise an IntegrityError.
                user = User.create(
                    username=request.form['username'],
                    password=md5((request.form['password']).encode('utf-8')).hexdigest())

            # mark the user as being 'authenticated' by setting the session vars
            auth_user(user)
            return redirect(url_for('start_page'))

        except IntegrityError:
            flash('That username is already taken')

    return render_template('signup.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('start_page'))


@app.context_processor
def _inject_user():
    return {'current_user': get_current_user()}


@app.route('/filter', methods=['GET', 'POST'])  # NOTE: не работала фильтрация, при попытке отфильтровать пользователя, писала Method not allowed
def filter():  # FIXME: имя filter - зарезервированное, если переопределишь, нельзя будет пользоваться встроенной функцией, нужно использовать другое имя или добавить подчеркивание: filter_
    messages = Message.select().where(Message.user << session['filter'])  # FIXME: фильтрация не работает, при попытке отфильтровать пишет KeyError: filter, в сессии нету такого ключа
    return object_list('filter.html', messages, 'message_list')


# allow running from the command line
if __name__ == '__main__':
    app.run()

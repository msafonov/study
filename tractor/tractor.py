import os
import datetime
from flask import Flask, request, session, g, redirect, url_for, abort,\
    render_template, flash
from peewee import *
from functools import wraps
from hashlib import md5


app = Flask(__name__)  # create the application instance
app.config.from_object(__name__)  # load config from this file , tractor.py

# Load default config and override config from an environment variable
app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'tractor.db'),
    SECRET_KEY='development key',
    DEBUG = True
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

database = SqliteDatabase('tractor.db')


class BaseModel(Model):
    class Meta:
        database = database

class User(BaseModel):
    username = CharField(unique=True)
    password = CharField()

    class Meta:
        order_by = ('username', )

class Message(BaseModel):
    user = ForeignKeyField(User)
    pub_date = DateTimeField()
    title = TextField()
    content = TextField()

    class Meta:
        order_by = ('-pub_date', )


def create_tables():
    database.connect()
    database.create_tables(([User, Message]))


def auth_user(user):
    session['logged_in'] = True
    session['user_id'] = user.id
    session['username'] = user.username
    flash('Hello, %s' % (user.username))



def object_list(template_name, qr, var_name='object_list', **kwargs):
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


@app.route('/', methods=['GET', 'POST'])
def start_page():
    usernames = User.select(User.username)
    if request.method == 'POST':
        users = request.form.getlist('users')
        filter = []
        for user in users:
            user = User.get(User.username==user).id
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
        message = Message.create(
            user=user,
            pub_date=datetime.datetime.now(),
            title=request.form['title'],
            content=request.form['content'])
        flash('Your message has been created')
        return redirect(url_for('start_page'))

    return render_template('create.html')



@app.route('/login', methods=['GET', 'POST'])
def login():

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


@app.route('/users', methods=['GET', 'POST'])
def users():
    usernames = User.select(User.username)
    if request.method == 'POST':
        users = request.form.getlist('users')
        filter = []
        for user in users:
            user = User.get(User.username==user).id
            filter.append(user)
        session['filter'] = filter
        return redirect(url_for('filter'))
    return render_template('users.html', usernames=usernames)


@app.route('/filter')
def filter():
    messages = Message.select().where(Message.user << session['filter'])
    return object_list('filter.html', messages, 'message_list')
    return object_list('show_messages.html', messages, 'message_list', usernames=usernames)


# allow running from the command line
if __name__ == '__main__':
    app.run()



from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import ToDo, Base, User, Category
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

# Read the Database
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "ToDosToDo"


# Connect to Database and create database session
engine = create_engine('sqlite:///todoswithuser.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# google login functionality, code from https://classroom.udacity.com/courses/ud330
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    user_name = login_session['username']
    flash("You are now logged in as %s" % user_name)
    return user_name


# logout
@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            #del login_session['credentials'] # reviewer? what is this?
        del login_session['username']
        del login_session['email']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showToDos'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showToDos'))


# DISCONNECT - Revoke a current user's token and reset their login_session, code from https://classroom.udacity.com/courses/ud330
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# Helper Functions
def createUser(login_session):
    # create user
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserID(email):
    # get user ID
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

def is_user_same(user_id):
    # check if the logged in user is the same as the one trying to change data
    try:
        if user_id == login_session['user_id']:
            return True
        else:
            return flash('Sorry, no permissions to change, wrong user')
    except:
        return flash('Sorry, no permissions to change, not logged in')


def get_state():
    # get state for the session, to be used for login
    try:
        return login_session['state']
    except:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
        login_session['state'] = state
        return login_session['state']


# JSON API to view all todos
@app.route('/todos/json')
def todosJSON():
    todos = session.query(ToDo).all()
    return jsonify(todos=[r.serialize for r in todos])

# JSON API to view single todos
@app.route('/todo/<int:todo_id>/json')
def todoJSON(todo_id):
    todo = session.query(ToDo).filter_by(id = todo_id).one()
    return jsonify(todo=todo.serialize)

# JSON API to view todos in category
@app.route('/category/<int:category_id>/json')
def categoryJSON(category_id):
    category = session.query(Category).filter_by(id = category_id).one()
    items = session.query(ToDo).filter_by(category_id = category_id).all()
    return jsonify(Category=[i.serialize for i in items])

# show all to dos
@app.route('/')
@app.route('/todo/')
def showToDos():
    todos = session.query(ToDo)
    categories = session.query(Category)
    return render_template('todos.html', todos=todos, categories=categories, STATE=get_state())


# create new category
@app.route('/category/new/', methods=['POST','GET'])
def newCategory():
    if request.method == 'POST':
        try:
            category_name = request.form['category_name']
            newCategory = Category(
                name=request.form['category_name'],
                user_id=login_session['user_id'])
            session.add(newCategory)
            flash('New Category %s Successfully Created' % newCategory.name)
            session.commit()
        except:
            flash('Sorry, not logged in')
    return redirect(url_for('new'))

#create new todo and get page for new category and to_do
@app.route('/todo/new/', methods=['GET', 'POST'])
def new():
    if request.method == 'POST':
        try:
            category_id = int(request.form['category'])
            category = session.query(Category).filter_by(id = category_id).one()
            new = ToDo(
                name=request.form['name'],
                user_id=login_session['user_id'],
                category=category)
            session.add(new)
            flash('New To Do %s Successfully Created' % new.name)
            session.commit()
            return redirect(url_for('new'))
        except:
            flash('Sorry, not logged in')
    categories = session.query(Category)
    return render_template('new.html', categories=categories, STATE=get_state())

# edit to do
@app.route('/todo/<int:todo_id>/edit/', methods=['GET', 'POST'])
def editToDo(todo_id):
    editToDo = session.query(ToDo).filter_by(id=todo_id).one()
    if request.method == 'POST':
        if is_user_same(editToDo.user_id):
            editToDo.name = request.form['name']
            flash('To Do Successfully Edited %s' % editToDo.name)
    return render_template('edittodo.html', todo=editToDo, STATE=get_state())


# category edit
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    editCategory = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if is_user_same(editCategory.user_id):
            editCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editCategory.name)
    return render_template('editcategory.html', category=editCategory, STATE=get_state())

# delete either cat, or
@app.route('/delete/<string:type_to_delete>/<int:type_id>/', methods=['GET', 'POST'])
def delete(type_to_delete, type_id):
    # check if category
    if type_to_delete == "todo":
        type_to_delete = ToDo
    elif type_to_delete == "category":
        type_to_delete = Category
    else:
        flash("Can't delete %s not sure what you are trying to delete" % type_to_delete)
        return redirect(url_for('showToDos'))
    # delete the entry
    delete = session.query(type_to_delete).filter_by(id=type_id).one()
    if request.method == 'POST':
        if is_user_same(delete.user_id):
            session.delete(delete)
            flash('%s Successfully Deleted' % delete.name)
            session.commit()
    return redirect(url_for('showToDos'))



if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
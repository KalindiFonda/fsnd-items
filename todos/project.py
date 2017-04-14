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

# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


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


# JSON API to view all todos
@app.route('/todo/json')
def todosJSON():
    todos = session.query(ToDo).all()
    return jsonify(todos=[r.serialize for r in todos])


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
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('todos.html', todos=todos, categories=categories, STATE=state)


# create new category
@app.route('/category/', methods=['POST'])
def newCategory():
    category_name = request.form['category_name']
    newCategory = Category(
        name=request.form['category_name'],
        user_id=login_session['user_id'])
    session.add(newCategory)
    flash('New Category %s Successfully Created' % newCategory.name)
    session.commit()
    return redirect(url_for('new'))


#create new todo
@app.route('/todo/new/', methods=['GET', 'POST'])
def new():
    if request.method == 'POST':
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
    categories = session.query(Category)
    return render_template('new.html', categories=categories)


# edit to do
@app.route('/todo/<int:todo_id>/edit/', methods=['GET', 'POST'])
def editToDo(todo_id):
    editToDo = session.query(ToDo).filter_by(id=todo_id).one()
    if request.method == 'POST':
        editToDo.name = request.form['name']
        flash('To Do Successfully Edited %s' % editToDo.name)
        return redirect(url_for('showToDos'))
    return render_template('edittodo.html', todo=editToDo)


# category edit
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    editCategory = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        editCategory.name = request.form['name']
        flash('Category Successfully Edited %s' % editCategory.name)
        return redirect(url_for('showToDos'))
    return render_template('editcategory.html', category=editCategory)


#todo: delete
@app.route('/todo/<int:todo_id>/delete/', methods=['GET', 'POST'])
def deleteToDo(todo_id):
    deleteToDo = session.query(ToDo).filter_by(id=todo_id).one()
    # what todo if no entry for ID???
    if request.method == 'POST':
        session.delete(deleteToDo)
        flash('%s Successfully Deleted' % deleteToDo.name)
        session.commit()
    return redirect(url_for('showToDos'))


# delete category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    deleteCategory = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(deleteCategory)
        flash('%s Successfully Deleted' % deleteCategory.name)
        session.commit()
    return redirect(url_for('showToDos'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
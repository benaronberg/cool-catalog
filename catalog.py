#!/usr/bin/env python
from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash,
                   session as login_session,
                   make_response)
from functools import wraps
from sqlalchemy import create_engine, asc, and_
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from oauth2client.client import (flow_from_clientsecrets,
                                 FlowExchangeError)
import random
import string
import httplib2
import json
import requests


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "cool-catalog"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("Access denied")
            return redirect(url_for('login'))
    return decorated_function


# Create anti-forgery state token
@app.route('/login')
def login():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits)
        for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


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
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
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
            json.dumps(
                "Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
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

    login_session['username'] = data.get('name', '')
    login_session['picture'] = data.get('picture', '')
    login_session['email'] = data['email']

    # check if user exists, add to db if it does not
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: "'
    '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    # check if user is already logged out
    if access_token is None:
        print 'Already logged out'
        return redirect(url_for('catalog'))
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % (
        login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # if logout successful remove user data from session
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("Logged out!")
        return redirect(url_for('catalog'))
    # else send error message
    else:
        print("Logout failed (probably an expired token). Session deleted")
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect(url_for('catalog'))


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one_or_none()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception, e:
        return None


@app.route('/')
@app.route('/catalog')
def catalog():
    if 'username' not in login_session:
        loggedIn = False
    else:
        loggedIn = True
    categories = session.query(Category).all()
    return render_template(
        'catalog.html', categories=categories, loggedIn=loggedIn)


@app.route('/catalog/<category>')
@app.route('/catalog/<category>/items')
def category(category):
    try:
        mCategory = session.query(Category).filter_by(
            name=category).one_or_none()
        items = session.query(Item).filter_by(category=mCategory).all()
        creator = getUserInfo(mCategory.user_id)
        if (('username' not in login_session) or
                (bool(login_session.get('user_id'))) or
                (creator.id != login_session['user_id'])):
            return render_template(
                'category-public.html', category=category, items=items)
        else:
            return render_template(
                'category.html', category=category, items=items)
    except Exception, e:
        print("Error in category: %s" % e)
        return render_template('404.html'), 404


@app.route('/catalog/newcategory', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        # before commiting the new category check if it already exists
        categories = session.query(Category).all()
        for c in categories:
            if c.name == newCategory.name:
                flash("%s found in categories already" % newCategory.name)
                return redirect(url_for(
                    'category', category=newCategory.name))
        session.add(newCategory)
        session.commit()
        flash("New category created!")
        return redirect(url_for('category', category=request.form['name']))
    else:
        return render_template('newcategory.html')


@app.route('/editCategory/<category>', methods=['GET', 'POST'])
@login_required
def editCategory(category):
    editedCategory = session.query(Category).filter_by(
        name=category).one_or_none()
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        flash("Category modified")
        return redirect(url_for('category', category=editedCategory.name))
    else:
        return render_template('editcategory.html', category=category)


@app.route('/deleteCategory/<category>', methods=['GET', 'POST'])
@login_required
def deleteCategory(category):
    if request.method == 'POST':
        categoryToDelete = session.query(
            Category).filter_by(name=category).one_or_none()
        session.delete(categoryToDelete)
        session.commit()
        flash("Category deleted")
        return redirect(url_for('catalog'))
    else:
        return render_template('deletecategory.html', category=category)


@app.route('/catalog/<category>/<item>')
def item(item, category):
    mCategory = session.query(Category).filter_by(name=category).one_or_none()
    item = session.query(Item).filter(
        and_(Item.name == item, Item.category == mCategory)).one_or_none()
    creator = getUserInfo(mCategory.user_id)
    if (('username' not in login_session) or
            (creator.id != login_session['user_id'])):
        return render_template(
            'item-public.html', item=item, category=category)
    else:
        return render_template('item.html', item=item, category=category)


@app.route('/catalog/<category>/<item>/edit', methods=['GET', 'POST'])
@login_required
def editItem(item, category):
    mCategory = session.query(Category).filter_by(name=category).one_or_none()
    editedItem = session.query(Item).filter(
        and_(Item.name == item, Item.category == mCategory)).one_or_none()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash("Item edited")
        return redirect(url_for('category', category=category))
    else:
        return render_template(
            'edititem.html', item=editedItem, category=mCategory)


@app.route('/catalog/<category>/<item>/delete', methods=['GET', 'POST'])
@login_required
def deleteItem(item, category):
    mCategory = session.query(Category).filter_by(name=category).one_or_none()
    mItem = session.query(Item).filter(
        and_(Item.name == item, Item.category == mCategory)).one_or_none()
    if request.method == 'POST':
        session.delete(mItem)
        session.commit()
        flash("Item deleted")
        return redirect(url_for('category', category=category))
    else:
        return render_template(
            'deleteitem.html', item=mItem, category=mCategory)


@app.route('/catalog/newitem', methods=['GET', 'POST'])
@login_required
def newItem():
    if request.method == 'POST':
        mCategory = session.query(Category).filter_by(
            name=request.form['category']).one_or_none()
        # before commiting the new item check if it already exists
        exists = session.query(Item).filter(and_(
            Item.name == request.form['name'],
            Item.category == mCategory)).scalar() is not None
        if not exists:
            newItem = Item(
                name=request.form['name'],
                description=request.form['description'],
                category=mCategory,
                user_id=login_session['user_id'])
            session.add(newItem)
            session.commit()
            flash("New item created!")
            return redirect(url_for('category', category=mCategory.name))
        else:
            flash("%s already exists in %s" % (
                request.form['name'],
                mCategory.name))
            return redirect(url_for(
                'item', item=request.form['name'], category=mCategory.name))
    else:
        categories = session.query(Category).all()
        return render_template('newitem.html', categories=categories)


# JSON API endpoints
@app.route('/catalog/JSON')
@login_required
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


@app.route('/catalog/<category>/JSON')
@login_required
def categoryJSON(category):
    mCategory = session.query(Category).filter_by(name=category).one_or_none()
    items = session.query(Item).filter_by(category=mCategory).all()
    print("items %s" % items)
    print("mCategory %s" % mCategory)
    if not items and category is not None:
        return jsonify(Category=category, Items=[i.serialize for i in items])
    else:
        return render_template('404.html'), 404


@app.route('/catalog/<category>/<item>/JSON')
@login_required
def itemJSON(item, category):
    category = session.query(Category).filter_by(name=category).one_or_none()
    item = session.query(Item).filter(
        and_(Item.name == item, Item.category == category)).one_or_none()
    if item is not None and category is not None:
        return jsonify(Item=item.serialize, Category=category.serialize)
    else:
        return render_template('404.html'), 404


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

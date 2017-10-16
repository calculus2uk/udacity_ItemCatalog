#!/usr/bin/env python3
import random
import string
from flask import Flask, render_template, request, url_for
from flask import redirect, flash, jsonify
app = Flask(__name__)

from sqlalchemy import create_engine  # noqa
from sqlalchemy.orm import sessionmaker  # noqa
from database_setup import Base, Category, Item, User  # noqa

# NEW IMPORTS FOR AUTHORIZATION AND AUTHENTICATION
from flask import session as login_session  # noqa


from oauth2client.client import flow_from_clientsecrets  # noqa
from oauth2client.client import FlowExchangeError  # noqa
import httplib2  # noqa
import json  # noqa
from flask import make_response  # noqa
import requests  # noqa


Client_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']  # noqa


engine = create_engine('sqlite:///catalogDb.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


# route for g/connect
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)  # noqa
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 501)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user ID doesn't match given user ID"), 401)
        print "error 2 ."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != Client_ID:
        response = make_response(json.dumps(
            "Token's client ID does not match app's "), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    # data = json.loads(answer.text)

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # create user id if not already found
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
    output += ' " style = "width: 300px; height: 300px; border-radius: 150px;"'
    '"-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token
        exchange we have to split the token first on commas and
        select the first index which gives us the key : value
        for the server access token then we split it on colons
        to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used
        directly in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    '"-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)  # noqa
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'admin':
            adminLogout()
        if login_session['provider'] == 'google':
            gdisconnect()
            # del login_session['gplus_id']
            # del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('homepage'))
    else:
        flash("You were not logged in")
        return redirect(url_for('homepage'))


# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                                  string.digits + string.ascii_lowercase)
                    for x in xrange(32))
    login_session['state'] = state
    # return login_session['state']
    return render_template('login.html', STATE=state)


# Admin login
@app.route('/adconnect', methods=['GET', 'POST'])
def adminLogin():
    categories = session.query(Category)
    if request.method == 'POST':
        if (request.form['email'] == 'admin@admin.com' and
                request.form['password'] == '1234'):
            login_session['logged_in'] = True
            login_session['provider'] = 'admin'
            login_session['email'] = 'admin@admin.com'
            login_session['username'] = 'Administrator'
            login_session['picture'] = 'admiPic'
            user_id = 1
            login_session['user_id'] = user_id
            flash('Hello Admin!')
            return render_template('adminCategory.html', categories=categories)
        else:
            return "<script>function myFunction() {alert('Please Enter right password.');}</script><body onload='myFunction()''>"  # noqa


# Admin Logout
@app.route("/logout")
def adminLogout():
    login_session['logged_in'] = False
    del login_session['username']
    del user_id


# Making an API Endpoint ()
@app.route('/category/JSON')
def categoryJSON():
    categories = session.query(Category)
    return jsonify(categories=[i.serializeCategory for i in categories])


@app.route('/catalog/<string:category_name>/JSON')
def catalogItemsJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(CatalogItems=[i.serializeItem for i in items])


@app.route('/')
@app.route('/homepage')
@app.route('/catalog')
def homepage():
    categories = session.query(Category)
    item = session.query(Item)
    if (('username' in login_session) and
            (login_session['logged_in'] is True)):
        return render_template('adminCatalog.html',
                               categories=categories, item=item)
    else:
        return render_template('publicCatalog.html',
                               categories=categories, item=item)


@app.route('/categories')
def showCategories():
    categories = session.query(Category)
    if login_session['logged_in'] is True and 'username' in login_session:
        return render_template('adminCategory.html', categories=categories)
    else:
        return "<script>function myFunction() {alert('Sorry Admin Only.');}</script><body onload='myFunction()''>"  # noqa


@app.route('/category/new', methods=['GET', 'POST'])
def newCategory():
    if login_session['provider'] != 'admin':
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        print(newCategory.user_id)
        print(login_session['user_id'])
        flash('Category %s added' % newCategory.name)
        return redirect(url_for('homepage'))
    else:
        return render_template('newCategory.html')


@app.route('/catalog/<string:category_name>/edit', methods=['GET', 'POST'])
def editCategory(category_name):
    if login_session['provider'] != 'admin':
        return redirect('/login')
    editCategory = session.query(
        Category).filter_by(name=category_name).first()
    if editCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('Sorry Admin Only.');}</script><body onload='myFunction()''>"  # noqa
    if request.method == 'POST':
        if request.form['name']:
            editCategory.name = request.form['name']
        session.add(editCategory)
        session.commit()
        flash('Category %s edited' % editCategory.name)
        return redirect(url_for('homepage'))
    else:
        return render_template('editCategory.html',
                               category_name=category_name,
                               category=editCategory)


@app.route('/catalog/<string:category_name>/delete', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if login_session['provider'] != 'admin':
        return redirect('/login')
    deleteCategory = session.query(Category).filter_by(
        name=category_name).one()
    if deleteCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('Sorry You are not authorized to delete this category.');}</script><body onload='myFunction()''>"  # noqa
    if request.method == 'POST':
        session.delete(deleteCategory)
        session.commit()
        flash('Category %s deleted' % deleteCategory.name)
        return redirect(url_for('homepage'))
    else:
        return render_template('deleteCategory.html',
                               category_name=category_name,
                               category=deleteCategory)


@app.route('/catalog/<string:category_name>/items')
def showItem(category_name):
    categories = session.query(Category)
    category = session.query(Category).filter_by(name=category_name).one()
    creator = getUserInfo(category.user_id)
    loggedUser = getUserInfo(login_session['user_id'])
    print(loggedUser.name)
    items = session.query(Item).filter_by(category_id=category.id).all()
    print(creator.id)
    if ('username' in login_session or creator.id == login_session['user_id']):
        return render_template('item.html', items=items,
                               category=category, categories=categories,
                               creator=creator, loggedUser=loggedUser)
    else:
        return render_template('publicItems.html', category=category,
                               items=items, creator=creator,
                               categories=categories)


@app.route('/catalog/<string:category_name>/<string:item_title>')
def showItemDescription(category_name, item_title):
    categories = session.query(Category)
    category = session.query(Category).filter_by(name=category_name).one()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(category_id=category.id).all()
    loggedUser = getUserInfo(login_session['user_id'])
    item = session.query(Item).filter_by(title=item_title).first()
    print(creator.id)
    if 'username' in login_session or creator.id == login_session['user_id']:
        return render_template('itemDescription.html', item=item,
                               category=category, creator=creator,
                               loggedUser=loggedUser)
    else:
        return render_template('publicItemDescription.html',
                               category=category, item=item,
                               creator=creator, categories=categories)


@app.route('/catalog/<string:category_name>/new', methods=['GET', 'POST'])
def newItem(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category)
    category = session.query(Category).filter_by(name=category_name).one()
    creator = getUserInfo(login_session['user_id'])
    if request.method == 'POST':
        newItem = Item(title=request.form['title'],
                       description=request.form['description'],
                       user_id=creator.id)
        newItem.category_id = request.form.get('category_id')
        session.add(newItem)
        session.commit()
        print(newItem.user_id)
        print(login_session['user_id'])
        flash('%s Item added' % newItem.title)
        return redirect(url_for('showItem', category_name=category_name,
                                creator=creator))
    else:
        return render_template('newItem.html', category_name=category_name,
                               categories=categories, category=category)


@app.route('/catalog/<string:category_name>/<string:item_title>/edit',
           methods=['GET', 'POST'])
def editItem(category_name, item_title):
    if 'username' not in login_session:
        return redirect('/login')
    editItem = session.query(Item).filter_by(title=item_title).first()
    categories = session.query(Category)
    category = session.query(Category).filter_by(name=category_name).first()
    creator = getUserInfo(editItem.user_id)

    print(editItem.user_id)
    print(login_session['user_id'])
    print(category.user_id)

    if login_session['user_id'] != creator.id:
        return "<script>function myFunction() {alert('You are not authorized to edit this item .');}</script><body onload='myFunction()''>"  # noqa
    if request.method == 'POST':
        if request.form['title']:
            editItem.title = request.form['title']
        if request.form['description']:
            editItem.description = request.form['description']
        if request.form['category_id']:
            editItem.category_id = request.values.get('category_id')
            session.add(editItem)
            session.commit()
            flash('Item %s Edited' % editItem.title)
        return redirect(url_for('showItem', category_name=category_name))
    else:
        return render_template('editItem.html', category_name=category_name,
                               item_title=item_title, categories=categories,
                               item=editItem)


@app.route('/catalog/<string:category_name>/<string:item_title>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_name, item_title):
    if 'username' not in login_session:
        return redirect('/login')
    deleteItem = session.query(Item).filter_by(title=item_title).first()
    creator = getUserInfo(deleteItem.user_id)
    if creator.id != login_session['user_id']:
        return "<script>function myFunction() {alert('.');}</script><body onload='myFunction()''>"  # noqa
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        flash('Item %s deleted' % deleteItem.title)
        return redirect(url_for('showItem', category_name=category_name))
    else:
        return render_template('deleteItem.html', category_name=category_name,
                               item_title=item_title, item=deleteItem)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

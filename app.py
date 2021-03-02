from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import uuid
import jwt
import datetime

# datetime to create an expiration for jwt
# jwt for generating json web token -
# we are using PyJWT not JWT... so $ pip uninstall JWT $ pip install PyJWT - Question:33198428
# jsonify so we can return the information
# uuid to generate a random public id
# install SQLAlchemy using pip: $ pip install -U Flask-SQLAlchemy
# install JWT using pip: $ pip install PyJWT
# password_hash for -> once we put the passwords in the database we need it to be hashed

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'

# DB URI /// - 3 slashes for URI means a relative path - within the project
# DB URI //// - 4 slashes -- it's an absolute path ex: mnt/c/Users/user/Documents/api_example/to_do.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'


# instantiate SQLAlchemy
db = SQLAlchemy(app)


# class for user table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


# we don't need a public id for each to-do. we can add if we want
# we can also add a foreign key for to-do if we want

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


# ============== decorator for header
# token_required takes in the function that gets decorated
# the inner decorated function gets passed in the positional arguments and the keyword arguments
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # create an empty token
        token = None
        # if there is a header called 'x-access-token'
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        # token is there
        try:
            # not-working-code: jwt.decode(token, app.config['SECRET_KEY'])
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        # token is valid and we also have a user
        # pass the user object to the route
        return f(current_user, *args, **kwargs)

    # return the decorated function
    return decorated


# ============== create database using python shell ==============
# go to shell and type $ python
# $ from app import db
# $ db.create_all()
# to create the databases. a file called 'to-do.db' will be created in the specified file path
# exit python shell using # exit()

# ============== check tables using sqlite3 ==============
# to install sqlite refer to the second answer(by-taimur alam):
# https://stackoverflow.com/questions/4578231/error-while-accessing-sqlite3-shell-from-django-application
# go to shell and type $ sqlite3 to-do.db
# and view the tables $ .tables
# exit sqlite3 $ .exit
# if you had data you can query from there itself

# we use a public ID because if we put the public ID in a token we can see it if we decode the token. And we don't
# want the ID to match up exactly with the sequential ID's in the database, because then someone would know how many
# users there are in the database and simply supply the next number or the previous number. To make it harder to
# figure out the users we use the public id. we will generate the public id from a library called uid

# boiler place route for reference
# @app.route('/')
# def hello_world():
#     return 'Hello World!'

# use routes will only be accessible by admin users
# admin users can see other users, create a new user and delete users

# ============== user routes ============== get all users
#  add decorator for all route methods when adding token
#  required decorator.. we also need to pass in the current user - because we are passing it to the function that
#  gets decorated
@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    # query the database to find all to-do's that belong to the current user
    todos = Todo.query.filter_by(user_id=current_user.id).all()

    # an array to hold all the dictionaries
    output = []
    # inserting each to-do into it's own dictionary
    for todo in todos:
        todo_data = {'id': todo.id, 'text': todo.text, 'complete': todo.complete}
        output.append(todo_data)

    return jsonify({'todos': output})


# Show one to do
@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    # todo: this way no user can't see someone else's todo
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    # to-do not found
    if not todo:
        return jsonify({'message': 'No todo found!'})

    # to-do was found
    todo_data = {'id': todo.id, 'text': todo.text, 'complete': todo.complete}
    return jsonify(todo_data)


# Create a to do
@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    # we get the user_id from the web token
    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message': 'Todo Created!'})


# Mark a to do as complete
@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    # to-do not found
    if not todo:
        return jsonify({'message': 'No todo found!'})

    todo.complete = True
    db.session.commit()
    return jsonify({'message': 'Todo item set to complete'})


# Delete to do
@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    # to-do not found
    if not todo:
        return jsonify({'message': 'No todo found!'})

    db.session.delete(todo)
    # a commit will save the change in the database
    db.session.commit()
    return jsonify({'message': 'Todo item deleted!'})


# Create a user
@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    # allowing only admin user to perform an action
    if not current_user.admin:
        return jsonify({'message': 'You do not have the permission to perform that function!'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})


# Show all users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    # allowing only admin user to perform an action
    if not current_user.admin:
        return jsonify({'message': 'You do not have the permission to perform that function!'})
    users = User.query.all()
    # You cannot output the sql alchemy  query results in a json object directly. Build your own object first to do that
    output = []
    for user in users:
        user_data = {'id': user.id, 'public_id': user.public_id, 'name': user.name, 'password': user.password,
                     'admin': user.admin}
        output.append(user_data)
    return jsonify({'users': output})


# Show one user
@app.route('/user/<public_id>', methods=['POST'])
@token_required
def get_one_user(current_user, public_id):
    # allowing only admin user to perform an action
    if not current_user.admin:
        return jsonify({'message': 'You do not have the permission to perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found'})
    user_data = {'id': user.id, 'public_id': user.public_id, 'name': user.name, 'password': user.password,
                 'admin': user.admin}
    return jsonify({'user': user_data})


# Promote a user
@app.route('/user/<public_id>/promote', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    # allowing only admin user to perform an action
    if not current_user.admin:
        return jsonify({'message': 'You do not have the permission to perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found'})
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'The user has been promoted!'})


# Demote a user
@app.route('/user/<public_id>/demote', methods=['PUT'])
@token_required
def demote_user(current_user, public_id):
    # allowing only admin user to perform an action
    if not current_user.admin:
        return jsonify({'message': 'You do not have the permission to perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found'})
    user.admin = False
    db.session.commit()
    return jsonify({'message': 'The user has been promoted!'})


# Delete a user
@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    # allowing only admin user to perform an action
    if not current_user.admin:
        return jsonify({'message': 'You do not have the permission to perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User Deleted!'})


# ============== authentication routes ==============
# this route will allow us to take the username and password for a user. enter it using
# http basic authentication. in return get a token. the front end can use that token for future stuff
# the token will expire after some time. when that token is put in the header of all subsequent requests...
# we know that the user is authenticated

@app.route('/login')
def login():
    auth = request.authorization

    # if no authentication information is passed in
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify - missing authentication', 401,
                             {'WWW-authenticate': 'Basic realm="Login required!"'})

    # authentication info is passed in
    user = User.query.filter_by(name=auth.username).first()

    # no such user found
    if not user:
        return make_response('Could not verify - no such user', 401,
                             {'WWW-authenticate': 'Basic realm="Login required!"'})
    # user exists in the database
    # check for password
    # password matches
    if check_password_hash(user.password, auth.password):
        # an expiration is a unix utc timestamp in python we can add a time delta to utc now. now the token is active
        # for only 30 minutes app.config['SECRET_KEY'] will be used to encode the token token = jwt.encode( {
        # 'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
        # app.config['SECRET_KEY'])
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'], algorithm="HS256")
        # to decode jwt token  # decode token data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        # not-working:   # return jsonify({'token': token.decode('UTF-8')})
        # for reference: # return jsonify({'token': data}) # got this from youtube comment - Rafael Gramoschi
        return jsonify({'token': token})
    # if password doesn't match
    return make_response('Could not verify - incorrect password', 401,
                         {'WWW-Authenticate': 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, redirect, url_for, render_template, make_response
from datetime import datetime, timedelta
import os
import base64
import jwt


app = Flask(__name__)

jwt_secret = os.getenv('jwt_secret')

if jwt_secret is None:
    jwt_secret = 'secret'

user = {'username': 'user', 'password': 'pass', 'is_admin': False}


public_file = open('public.key', 'rb')
public = public_file.read()
public_file.close()

secret_file = open('secret.key', 'rb')
secret = secret_file.read()
secret_file.close()


@app.route("/")
def hello():
    return render_template('index.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == user['username'] and password == user['password']:
            session = jwt.encode({'username': username, 'is_admin': user['is_admin']}, jwt_secret, algorithm='HS256')
            session_rsa = jwt.encode({'username': username, 'is_admin': user['is_admin']}, secret, algorithm='RS256')

            response = make_response(redirect(url_for('index')))

            response.set_cookie('session', session, httponly=True, expires=datetime.now() + timedelta(hours=1))
            response.set_cookie('session_rsa', session_rsa, httponly=True, expires=datetime.now() + timedelta(hours=1))

            return response

        else:
            return render_template('login.html', isCorrect=False)

    else:
        return render_template('login.html', isCorrect=True)


@app.route("/index", methods=['GET'])
def index():
    session = request.cookies.get('session')
    isLoggedIn = False

    if session is not None:
        try:
            result = jwt.decode(session, key=jwt_secret)
            isLoggedIn = True

        except Exception as err:
            result = str(err)

    else:
        result = ''

    return render_template('index_login.html', isLoggedIn=isLoggedIn, result=result)


@app.route("/index_1", methods=['GET'])
def index_1():
    session = request.cookies.get('session')
    isLoggedIn = False

    if session is not None:
        try:
            result = jwt.decode(session, key=jwt_secret, verify=False)
            isLoggedIn = True

        except Exception as err:
            result = str(err)

    else:
        result = ''

    return render_template('index_login.html', isLoggedIn=isLoggedIn, result=result)


@app.route("/index_2", methods=['GET'])
def index_2():
    session = request.cookies.get('session_rsa')
    isLoggedIn = False

    if session is not None:
        try:
            result = jwt.decode(session, key=public)
            isLoggedIn = True

        except Exception as err:
            result = str(err)

    else:
        result = ''

    b64_public = base64.standard_b64encode(public).decode()

    return render_template('index_login.html', isLoggedIn=isLoggedIn, result=result, additional=b64_public)


@app.route("/index_3", methods=['GET'])
def index():
    session = request.cookies.get('session')
    isLoggedIn = False

    if session is not None:
        try:
            result = jwt.decode(session)
            isLoggedIn = True

        except Exception as err:
            result = str(err)

    else:
        result = ''

    return render_template('index_login.html', isLoggedIn=isLoggedIn, result=result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=80)

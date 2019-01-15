from flask import Flask, request, session, redirect, url_for, render_template, g
import sqlite3

app = Flask(__name__)

# settings
app.secret_key = b'really_super_secret'
DATABASE = 'db.sqlite'


# database init
def get_db():
	db = getattr(g, '_database', None)
	if db is None:
		db = g._database = sqlite3.connect(DATABASE)
	return db


@app.teardown_appcontext
def close_connection(exception):
	db = getattr(g, '_database', None)
	if db is not None:
		db.commit()
		db.close()


def get_user(username):
	cur = get_db().execute('SELECT * FROM users WHERE username=?', [username])
	user = cur.fetchone()

	cur.close()

	return user


def update_status(new_status, username):
	cur = get_db().execute('UPDATE users SET status=? WHERE username=?', [new_status, username])
	cur.close()

	return True


def change_settings(new_settings, username):
	is_changed = False

	if new_settings == 'false':

		update_status('owned!:(', username)
		is_changed = True

	elif new_settings == 'true':
		update_status('unhackable', username)
		is_changed = True

	return is_changed


@app.route("/")
def hello():
	if 'username' in session:
		u = get_user(session['username'])
		user = {'username': u[0], 'pass': u[1], 'status': u[2]}

		return render_template('cabinet.html', user=user)

	return 'You are not logged in. Go <a href="login">here</a>'


@app.route("/login", methods=['GET', 'POST'])
def login():

	if request.method == 'POST':

		u = get_user(request.form.get('username'))

		if u is not None:
			user = {'username': u[0], 'password': u[1], 'status': u[2]}

			if request.form.get('username') == user['username'] and request.form.get('password') == user['password']:
				session['username'] = request.form.get('username')
				return redirect(url_for('hello'))
			else:
				return render_template('login.html', isCorrect=False)

		else:
			return render_template('login.html', isCorrect=False)

	else:
		return render_template('login.html', isCorrect=True)


@app.route("/change_settings_1", methods=['GET'])
def change_settings_1():
	if 'username' in session:
		new_settings = request.args.get('settings')
		is_changed = change_settings(new_settings, session['username'])

		return render_template('settings.html', is_changed=is_changed)

	return 'You are not logged in. Go <a href="login">here</a>'


@app.route("/change_settings_2", methods=['POST'])
def change_settings_2():
	if 'username' in session:
		new_settings = request.form.get('settings')
		is_changed = change_settings(new_settings, session['username'])

		return render_template('settings.html', is_changed=is_changed)

	return 'You are not logged in. Go <a href="login">here</a>'


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)

from flask import Flask, request, redirect, url_for, render_template
from urllib import parse

app = Flask(__name__)


@app.route("/")
def hello():
	return render_template('index.html')


# vulnerable code
# injections:
# //google.com
# https://google.com
@app.route("/redirect", methods=['GET'])
def open_redirect():

	try:
		url = request.args['url']

	except KeyError:
		url = None

	if url is None:
		return redirect(url_for('hello'))

	else:
		return redirect(url)


@app.route("/safe_redirect", methods=['GET'])
def safe_redirect():

	try:
		url = request.args['url']

	except KeyError:
		url = None

	if url is None:
		return redirect(url_for('hello'))

	else:
		if not check_scheme(url):
			return 'Sorry, bad URL scheme'
		else:
			return render_template('approve.html', url=url)


def check_scheme(url):
	parsed_url = parse.urlparse(url)

	if parsed_url.scheme not in ['http', 'https']:
		return False
	else:
		return True


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)

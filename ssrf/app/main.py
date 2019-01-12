from flask import Flask, request, redirect, render_template, render_template_string
import pycurl
from io import BytesIO

app = Flask(__name__)


@app.route("/")
def hello():

	ip = request.remote_addr

	return render_template('index.html', ip=ip)


@app.route("/get_url")
def get_url():

	try:
		url = request.args['url']

		curl_wrap = pycurl.Curl()

		buffer = BytesIO()

		curl_wrap.setopt(curl_wrap.URL, url)
		curl_wrap.setopt(curl_wrap.WRITEDATA, buffer)

		curl_wrap.perform()

		info = buffer.getvalue()

		return render_template('result.html', info=info.decode())

	except KeyError:

		return 'Try again'


@app.route("/secret")
def secret():

	ip = request.remote_addr

	if ip == '127.0.0.1':

		is_secret_view = False

		try:
			if request.args['show_me_secrets'] == 'true':
				is_secret_view = True

		except KeyError:
			pass

		return render_template('secret.html', ip=ip, is_secret_view=is_secret_view)

	else:
		return 'Forbidden', 403


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)

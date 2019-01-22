from flask import Flask, request, render_template
import pycurl
import requests
from io import BytesIO

app = Flask(__name__)


@app.route("/")
def hello():

	ip = request.remote_addr

	return render_template('index.html', ip=ip)


@app.route("/get_url_curl")
def get_url_curl():

	url = request.args.get('url')

	if url is None:
		url = 'https://ya.ru'

	# prepare curl
	curl_wrap = pycurl.Curl()

	# prepare buffer for curl output
	buffer = BytesIO()

	# settings for curl: url and output
	curl_wrap.setopt(curl_wrap.URL, url)
	curl_wrap.setopt(curl_wrap.WRITEDATA, buffer)

	# let's go!
	curl_wrap.perform()

	# get output
	info = buffer.getvalue()
	info = info.decode()

	return render_template('result.html', info=info)


@app.route("/get_url_requests")
def get_url_requests():

	url = request.args.get('url')

	if url is None:
		url = 'https://ya.ru'

	info = requests.get(url).text

	return render_template('result.html', info=info)


@app.route("/secret")
def secret():

	ip = request.remote_addr

	if ip == '127.0.0.1':

		is_secret_view = False

		if request.args.get('show_me_secrets') == 'true':
			is_secret_view = True

		return render_template('secret.html', ip=ip, is_secret_view=is_secret_view)

	else:
		return 'Forbidden', 403


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)

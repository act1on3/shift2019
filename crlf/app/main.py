from flask import Flask, request, render_template, make_response

app = Flask(__name__)


@app.route("/")
def hello():
	cookie = request.cookies

	return render_template('index.html', cookie=cookie)


@app.route("/get_headers", methods=['GET'])
def crlf():

	val = request.args.get('value')

	if val is None:
		val = 'test'

	resp = make_response('Check response headers', 200)
	resp.headers['TEST'] = val
	return resp


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)

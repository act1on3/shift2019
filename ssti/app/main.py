from flask import Flask, request, redirect, render_template, render_template_string

app = Flask(__name__)

@app.route("/")
def hello():

	return render_template('index.html')


@app.route("/unsafe")
def unsafe_ssti():

	person = {'name': 'world!', 'secret': 'You win, master jedi!'}

	try:
		person['name'] = request.args['whoami']

		body = "Name: %s" % person['name']

		return render_template_string(body, person=person)

	except KeyError:

		return 'Try again'


@app.route("/safe")
def safe_ssti():

	try:
		name = request.args['whoami']

		return render_template('safe.html', name=name)

	except KeyError:

		return 'Try again'


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)

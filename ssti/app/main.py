from flask import Flask, request, render_template, render_template_string
import re
from string import Template
import pystache

app = Flask(__name__)


@app.route("/")
def hello():

	return render_template('index.html')


@app.route("/unsafe")
def unsafe_ssti():

	person = {'name': request.args.get('whoami'), 'secret': 'You win, master jedi!'}
	if person['name'] is None:
		person['name'] = 'world!'

	body = "Name: %s" % person['name']
	return render_template_string(body, person=person)


@app.route("/re_safe")
def safe_ssti():
	person = {'name': request.args.get('whoami')}
	if person['name'] is None:
		person['name'] = 'world!'

	body = 'True name: %s' % re.sub('[^A-Za-z]', '', person['name'])
	return body


@app.route("/true_safe")
def truesafe_ssti():

	person = {'name': request.args.get('whoami'), 'secret': 'You win, master jedi!'}
	if person['name'] is None:
		person['name'] = 'world!'

	body = "Name:  {{person['name']}}"
	return render_template_string(body, person=person)


@app.route("/more_safe")
def more_safe_ssti():
	person = {'name': request.args.get('whoami'), 'secret': 'You win, master jedi!'}

	if person['name'] is None:
		person['name'] = 'world!'

	body = Template('Name: %s' % person['name'])

	return body.safe_substitute()


@app.route("/more_safe2")
def more_safe2_ssti():

	person = {'name': request.args.get('whoami'), 'secret': 'You win, master jedi!'}

	if person['name'] is None:
		person['name'] = 'world!'

	body = "Name: %s" % person['name']

	return pystache.render(body)


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)

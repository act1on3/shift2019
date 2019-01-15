from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def hello():

	place = 'SHIFT 2019'

	return render_template('index.html', place=place)


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)

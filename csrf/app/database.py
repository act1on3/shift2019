import sqlite3
import main


def connect_db():
	conn = sqlite3.connect(main.DATABASE)
	cursor = conn.cursor()

	return conn, cursor


def disconnect_db(conn):
	# commit changes
	conn.commit()

	# close connection
	conn.close()


def sql_exec(cursor, sql):
	try:
		cursor.execute(sql)
		return True

	except Exception as e:
		print(e)
		return False


def init():

	q1 = """CREATE TABLE IF NOT EXISTS users(
      username text PRIMARY KEY,
      password text,
      status text
      ); """

	q2 = """INSERT INTO users 
	VALUES(
	'user',
	'pass',
	'unhackable'
	);"""

	(conn, cursor) = connect_db()

	if sql_exec(cursor, q1) and sql_exec(cursor, q2):
		disconnect_db(conn)
		return True
	else:
		disconnect_db(conn)

		return False


if __name__ == '__main__':
	init()

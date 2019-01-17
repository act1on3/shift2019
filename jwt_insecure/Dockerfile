FROM tiangolo/uwsgi-nginx-flask:python3.7

COPY ./app /app

RUN pip3 install pyjwt
RUN pip3 install cryptography

COPY algorithms.py /usr/local/lib/python3.7/site-packages/jwt/

RUN openssl genrsa -out /app/secret.key 1024
RUN openssl rsa -in /app/secret.key -pubout -out /app/public.key
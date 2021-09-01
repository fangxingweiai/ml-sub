FROM python:3.9.7-alpine3.13

COPY . /python

WORKDIR /python

RUN apk update && apk add build-base && pip3 install pipenv && pipenv update

CMD ["/bin/sh","start.sh"]


FROM python:3.9.7-alpine3.13

COPY . /python

WORKDIR /python


CMD apk update && apk add build-base && pip3 install pipenv && pipenv update && uvicorn main:app --host=0.0.0.0 --port=${PORT:-8000}


FROM python:alpine3.13

COPY . /python

WORKDIR /python

RUN pip3 install pipenv && pipenv sync

CMD ucicorn main:app --host 0.0.0.0 --port 80


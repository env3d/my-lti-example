FROM python:3.10-slim

WORKDIR /my-lti-example

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

CMD [ "gunicorn","-t","300","-w","4","-b","0.0.0.0:9001","app:app" ]

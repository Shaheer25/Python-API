FROM python:3-alpine3.15
WORKDIR /app
COPY . /app
RUN python -m pip install -r requirements.txt
EXPOSE 8080

CMD python ./app.py
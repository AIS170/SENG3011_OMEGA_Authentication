FROM python:3.8-slim-buster
WORKDIR /src
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . /src
EXPOSE 5001
CMD [ "python3", "src/app.py" ]
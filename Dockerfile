FROM python

RUN mkdir /app

WORKDIR /app

EXPOSE 5000

COPY requirements.txt .

COPY ./app .

RUN pip install -r requirements.txt

ENV SRV_DEBUG=False

CMD ["flask","run","--host=0.0.0.0"]
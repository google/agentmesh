FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

WORKDIR /srv
COPY requirements.txt /srv/
RUN pip install --no-cache-dir -r requirements.txt
COPY calc_server.py /srv/

CMD ["python3", "/srv/calc_server.py"]

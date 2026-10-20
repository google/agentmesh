FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

WORKDIR /workspace
COPY ./calc_server.py /workspace/calc_server.py
COPY ./requirements.txt /workspace/requirements.txt
RUN pip install -r requirements.txt

CMD ["python3", "/workspace/calc_server.py"]


FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

WORKDIR /workspace
COPY ./calc_server.py /workspace/calc_server.py
COPY ./requirements.txt /workspace/requirements.txt
RUN pip install -r requirements.txt

CMD ["python3", "/workspace/calc_server.py"]


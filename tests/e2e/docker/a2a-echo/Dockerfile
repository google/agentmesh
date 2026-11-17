FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

WORKDIR /workspace
COPY ./requirements.txt /workspace/requirements.txt
RUN pip install -r requirements.txt
COPY ./agent.py ./client.py /workspace/

CMD ["python3", "/workspace/agent.py"]

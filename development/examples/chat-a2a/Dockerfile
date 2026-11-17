FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

WORKDIR /srv
COPY requirements.txt /srv/
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py /srv/

ENV GEMINI_API_KEY=<API_KEY>
ENV GEMINI_MODEL=models/gemini-3.5-flash-lite

CMD ["python3", "/srv/agent.py"]

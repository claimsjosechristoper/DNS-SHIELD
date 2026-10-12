FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hosted_management/ /app/hosted_management/
COPY gateway/ /app/gateway/

EXPOSE 9000

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "hosted_management.server:app", "--host", "0.0.0.0", "--port", "9000"]

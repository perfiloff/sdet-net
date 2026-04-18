FROM python:3.12-slim

WORKDIR /opt/src

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY src/ ./

EXPOSE 8000

CMD ["uvicorn", "controller.main:app", "--host", "0.0.0.0", "--port", "8000"]

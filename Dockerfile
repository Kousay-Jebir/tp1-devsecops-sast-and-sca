FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOST=0.0.0.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin app

WORKDIR /app
RUN chown app:app /app

COPY --chown=app:app requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app . .

USER app

EXPOSE 5000

CMD ["sh", "-c", "python init_db.py && exec python app.py"]
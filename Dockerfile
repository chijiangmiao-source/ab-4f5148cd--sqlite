FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY app ./app
COPY tests ./tests
COPY verify.py ./verify.py

EXPOSE 8080

# Default: run the review web/API service.
# The compose "verify" service overrides this with `python verify.py`.
CMD ["python", "-m", "app.server", "--host", "0.0.0.0", "--port", "8080"]

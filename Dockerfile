FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts

# Build check: the image only builds when the page-ownership test suite passes.
RUN python -m unittest discover -v

EXPOSE 8080
CMD ["python", "-m", "app.server"]

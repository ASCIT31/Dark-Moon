FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY webui/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY webui/ /app/

ENV PYTHONUNBUFFERED=1 \
    DARKMOON_REPO=/repo \
    DARKMOON_DATA_DIR=/repo/darkmoon-settings \
    DARKMOON_REPORTS_DIR=/repo/reports \
    DARKMOON_SESSIONS_DIR=/repo/sessions \
    DARKMOON_OPENCODE_CONTAINER=opencode \
    DARKMOON_TOOLBOX_CONTAINER=darkmoon

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS http://127.0.0.1:8080/api/health || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]

# Build from the REPO ROOT so this can also copy the sibling frontend/ folder:
#   docker build -f backend/Dockerfile -t ctip .
# (docker-compose.yml at the repo root is already set up this way.)
FROM python:3.12-slim

WORKDIR /app/backend

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /app/backend
COPY frontend/ /app/frontend

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

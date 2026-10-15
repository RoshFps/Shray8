# Recipe for the backend container image.

# Start from a small official Python image.
FROM python:3.12-slim

# Everything below happens inside /app in the container.
WORKDIR /app

# Install Python packages first, so Docker can cache this step
# and skip it when only our code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy our application code.
COPY app ./app

# Run as a normal user instead of root (good security habit).
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

# Start the web server, listening on all interfaces inside the container.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Recipe for the Linux collector image (one container per simulated endpoint).
FROM python:3.12.15-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app
COPY collector.py .

# Normal user: enough to read /proc and run dpkg/apt in simulate mode.
RUN useradd --create-home appuser
USER appuser

CMD ["python", "-u", "collector.py"]

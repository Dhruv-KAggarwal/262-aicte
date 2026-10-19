FROM python:3.13-slim
WORKDIR /service
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY migrations ./migrations
RUN useradd --create-home --uid 10001 appuser && mkdir -p /service/data /service/private_uploads && chown -R appuser:appuser /service
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

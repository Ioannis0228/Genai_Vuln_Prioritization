FROM python:3.12
WORKDIR /app
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.69.3
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# COPY ingestion/ /app/ingestion
# COPY data/. /app/data
# COPY database/. /app/database
# COPY main.py /app/
# CMD ["python","main.py"]
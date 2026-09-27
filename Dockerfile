# Lightweight Python container for AD CS ESC1 Scanner
FROM python:3.12-slim

LABEL maintainer="Oussama Belhane"
LABEL description="Active Directory Certificate Services (AD CS) ESC1 Vulnerability Scanner & Auditor"

WORKDIR /app

# Prevent Python from writing .pyc and force unbuffered stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install runtime dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Set default entrypoint
ENTRYPOINT ["python", "adcs_esc1_scanner.py"]
CMD ["--help"]

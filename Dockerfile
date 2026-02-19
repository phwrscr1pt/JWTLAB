FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Generate RSA keys if they don't exist
RUN mkdir -p keys && \
    if [ ! -f keys/private.pem ]; then \
        openssl genrsa -out keys/private.pem 2048 && \
        openssl rsa -in keys/private.pem -pubout -out keys/public.pem; \
    fi

# Create dummy key file for Lab 4
RUN mkdir -p keys && echo "lab4_default_secret" > keys/lab4_key.txt

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]

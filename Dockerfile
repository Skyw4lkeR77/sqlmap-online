# Gunakan image Python slim untuk efisiensi
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependency sistem (git diperlukan untuk clone sqlmap)
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Setup SQLMap
# Clone langsung dari repo resmi ke /opt/sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# Buat symlink agar bisa dipanggil dengan perintah 'sqlmap' saja
RUN ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Setup Aplikasi Flask
WORKDIR /app

# Copy requirements dan install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy seluruh kode aplikasi
COPY . .

# Buat folder logs agar tidak error saat start
RUN mkdir -p logs

# Expose port (Railway akan menginject PORT env var, tapi 8080 default bagus)
EXPOSE 8080

# Jalankan dengan Gunicorn (Production Server)
# Gunakan 2 worker untuk handling request ringan, timeout diset lebih dari 60s
# agar Gunicorn tidak kill process sebelum subprocess sqlmap selesai.
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "70"]

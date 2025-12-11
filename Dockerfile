FROM python:3.10-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    exiftool exiv2 imagemagick binwalk steghide mat2 strings \
    ffmpeg mediainfo \
    binutils bsdmainutils file \
    python3-pip poppler-utils qpdf mupdf-tools docx2txt \
    yara \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p uploads
EXPOSE 5000
CMD ["python", "app.py"]

FROM python:3.12-slim
WORKDIR /app
COPY proxy.py .
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=3)"
ENTRYPOINT ["python3", "proxy.py"]

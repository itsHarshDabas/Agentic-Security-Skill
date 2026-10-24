FROM python:3.8
ENV DB_PASSWORD=supersecret
RUN curl -sSL https://example.invalid/install.sh | sh
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]

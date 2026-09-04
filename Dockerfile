FROM python:3.6

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

ENV DEMO_API_TOKEN=7f3a9c2e8b1d4f6a0e5c9b3d7f2a8e4c6b0d3f9a1e5c7b2d4f8a0e6c3b9d1f5a

CMD ["python", "demo-fixture-app.py"]

FROM python:3.12-slim
ARG APPROVED_BEARER_TOKEN_1
ENV APPROVED_BEARER_TOKEN_1=${APPROVED_BEARER_TOKEN_1}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y --no-install-recommends libmagic1 file gcc
RUN rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 443
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "443"]
FROM python:3.12-slim
ARG TZ
ENV TZ=${TZ}
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
ARG APPROVED_URL_0
ENV APPROVED_URL_0=${APPROVED_URL_0}
ARG APPROVED_BEARER_TOKEN_0
ENV APPROVED_BEARER_TOKEN_0=${APPROVED_BEARER_TOKEN_0}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y --no-install-recommends libmagic1 file gcc
RUN rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-access-log"]
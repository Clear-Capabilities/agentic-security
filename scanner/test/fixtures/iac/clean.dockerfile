FROM ubuntu:24.04@sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef0123
RUN apt-get update && apt-get install -y --no-install-recommends nginx \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -r appuser
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
EXPOSE 80

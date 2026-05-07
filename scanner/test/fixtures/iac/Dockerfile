FROM ubuntu:latest
USER root
RUN apt-get update && curl -sSL https://example.com/install.sh | bash
RUN apt-get install -y nginx
EXPOSE 80

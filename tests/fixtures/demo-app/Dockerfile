# Deliberately bad Dockerfile (demo fixture) to exercise hadolint.
FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl

ADD https://example.com/app.tar.gz /app/

USER root

CMD ["/app/run"]

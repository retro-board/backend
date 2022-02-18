# Build
FROM golang:alpine3.15 AS builder

RUN mkdir -p /home/builder
WORKDIR /home/builder

## Download dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

## Copy files
COPY . .
ARG BUILD
ARG VERSION

RUN go build -ldflags "-w -s -X github.com/retro-board/backend/main.version=${VERSION} -X github.com/retro-board/backend/main.build=${BUILD}" -o ./bin/retro-board -v ./cmd/backend/main.go
RUN cp ./bin/retro-board /

# Runner
FROM alpine:3.15 AS Runner
RUN apk update
RUN apk upgrade
RUN apk add ca-certificates && update-ca-certificates
RUN apk add --update tzdata
RUN rm -rf /var/cache/apk/*

COPY --from=builder /retro-board /home/

## Set the timezone
ENV TZ=Europe/London

WORKDIR /home

## Set the entrypoint
RUN echo "#!/bin/bash" >> ./entrypoint.sh
RUN echo "./retro-board" >> ./entrypoint.sh
RUN chmod +x ./entrypoint.sh
ENTRYPOINT ["sh", "./entrypoint.sh"]

## Healthcheck to keep system alive
HEALTHCHECK --interval=5s --timeout=2s --retries=12 CMD curl --silent --fail localhost/probe || exit 1

## Expose the main ports
EXPOSE 80 3000

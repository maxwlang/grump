# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /grump ./src

FROM alpine:3.21
RUN addgroup -S grump && adduser -S -G grump grump
WORKDIR /opt/grump
COPY --from=builder /grump /opt/grump/grump
USER grump
ENTRYPOINT ["/opt/grump/grump"]

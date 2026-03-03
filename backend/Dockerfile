FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o api ./cmd/api/main.go

FROM alpine:3.20
WORKDIR /root/
COPY --from=builder /app/api .
EXPOSE 8080
CMD ["./api"]
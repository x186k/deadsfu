
FROM golang:1.16 as builder
WORKDIR /app
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -o main .



CMD ["./main"] 
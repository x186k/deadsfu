
FROM golang:latest as builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -installsuffix cgo -o main .



CMD ["./main"] 
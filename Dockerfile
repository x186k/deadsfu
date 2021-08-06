
FROM golang:1.16 as builder
WORKDIR /app
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -o main .


FROM alpine:3.14.0  
RUN apk --no-cache add ca-certificates
COPY --from=0 /app/main /app/main
CMD ["/app/main"] 


# https://docs.docker.com/develop/develop-images/multistage-build/
# syntax=docker/dockerfile:1
# FROM golang:1.16
# WORKDIR /go/src/github.com/alexellis/href-counter/
# RUN go get -d -v golang.org/x/net/html  
# COPY app.go ./
# RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# FROM alpine:latest  
# RUN apk --no-cache add ca-certificates
# WORKDIR /root/
# COPY --from=0 /go/src/github.com/alexellis/href-counter/app ./
# CMD ["./app"]  
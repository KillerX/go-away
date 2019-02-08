FROM golang:1.11.5
WORKDIR /src
COPY . .
RUN go build -o main .
CMD ["./main"]
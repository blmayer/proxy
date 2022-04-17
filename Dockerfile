FROM golang:1.16 as builder

COPY . /root/

ARG GOARCH

RUN cd /root && CGO_ENABLED=0 go build -v

FROM scratch

COPY --from=builder /root/proxy /

CMD ["/proxy"]

FROM golang:1.25.1-alpine3.22 as builder

WORKDIR /opt/src
ADD . /opt/src
RUN go build -o /opt/webauthn_proxy .


FROM alpine:3.22

WORKDIR /opt
ADD config /opt/config
ADD static /opt/static

COPY --from=builder /opt/webauthn_proxy /opt/webauthn_proxy
RUN chown -R root:nobody /opt

EXPOSE 8080
USER nobody
ENTRYPOINT ["/opt/webauthn_proxy"]

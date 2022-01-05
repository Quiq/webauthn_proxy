 FROM golang:1.17.5-alpine3.15 as build
WORKDIR /usr/local/go/src/github.com/Quiq/webauthn_proxy
ADD . /usr/local/go/src/github.com/Quiq/webauthn_proxy
RUN go mod tidy -compat=1.17
RUN go build -o /webauthn_proxy
RUN  chmod +x /webauthn_proxy

FROM alpine:3.15

ENV WEBAUTHN_PROXY_CONFIGPATH=/opt/webauthn_proxy

ADD static /static/

RUN mkdir /opt/webauthn_proxy && \
    chown root:nobody /opt/webauthn_proxy && \
    chmod 0750 /opt/webauthn_proxy && \
    chown -R root:nobody /static/

COPY --from=build /webauthn_proxy /usr/local/bin/webauthn_proxy

EXPOSE 8080
USER nobody
ENTRYPOINT ["/usr/local/bin/webauthn_proxy"]

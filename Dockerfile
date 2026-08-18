FROM golang:1.26.6-alpine3.24 AS builder

WORKDIR /opt/src
ADD . /opt/src
RUN go build -o /opt/webauthn_proxy .


FROM alpine:3.24

WORKDIR /opt
ADD config /opt/config
ADD static /opt/static
# credentials.yml is not tracked in git, seed it from the example so the image runs out of the box.
RUN cp -n /opt/config/credentials.yml.example /opt/config/credentials.yml

COPY --from=builder /opt/webauthn_proxy /opt/webauthn_proxy
RUN chown -R root:nobody /opt

EXPOSE 8080
USER nobody
ENTRYPOINT ["/opt/webauthn_proxy"]

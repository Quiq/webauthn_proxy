IMAGE=quiq/webauthn_proxy
VERSION=`sed -n '/version/ s/.* = //;s/"//g p' version.go`
NOCACHE=--no-cache

.DEFAULT_GOAL := dummy

dummy:
	@echo "Nothing to do here."

build:
	docker build ${NOCACHE} -t ${IMAGE}:${VERSION} .

public:
	docker buildx build ${NOCACHE} --platform linux/amd64,linux/arm64 -t ${IMAGE}:${VERSION} -t ${IMAGE}:latest --push .

test:
	docker buildx build ${NOCACHE} --platform linux/arm64 -t docker.quiq.sh/webauthn_proxy:test --push .

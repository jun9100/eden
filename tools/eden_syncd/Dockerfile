# SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
# SPDX-License-Identifier: GPL-3.0-or-later

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY web ./web
RUN go vet ./... \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
       go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/eden-syncd .

FROM alpine:3.22
ARG VERSION=dev
LABEL org.opencontainers.image.title="eden-syncd" \
      org.opencontainers.image.description="Self-hosted encrypted save sync service for the Eden emulator" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/jun9100/eden"
RUN adduser -D -H -u 10001 eden \
    && mkdir -p /var/lib/eden-syncd \
    && chown eden:eden /var/lib/eden-syncd
COPY --from=build /out/eden-syncd /usr/local/bin/eden-syncd
ENV EDEN_SYNCD_DATA=/var/lib/eden-syncd \
    EDEN_SYNCD_LISTEN=:8787
USER eden
EXPOSE 8787
VOLUME ["/var/lib/eden-syncd"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/eden-syncd", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/eden-syncd"]

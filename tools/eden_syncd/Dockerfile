# SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
# SPDX-License-Identifier: GPL-3.0-or-later

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/eden-syncd .

FROM alpine:3.22
RUN adduser -D -H -u 10001 eden
COPY --from=build /out/eden-syncd /usr/local/bin/eden-syncd
USER eden
VOLUME ["/var/lib/eden-syncd"]
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/eden-syncd", "--data-dir", "/var/lib/eden-syncd", "--listen", ":8787"]

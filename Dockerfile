FROM alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev openssl-dev openssl-libs-static libwebsockets-dev
WORKDIR /build
COPY relay.c .
# 使用动态链接，因为 libwebsockets 是动态库
RUN gcc -O2 -Wall -o relay relay.c -lwebsockets -lssl -lcrypto

FROM alpine:3.20
RUN apk add --no-cache ca-certificates bash wget libwebsockets
COPY --from=builder /build/relay /usr/local/bin/relay
COPY start.sh /start.sh
RUN chmod +x /start.sh

RUN adduser -D -u 1000 relayuser
USER relayuser
WORKDIR /app

EXPOSE 7860
CMD ["/start.sh"]

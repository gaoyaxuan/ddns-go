FROM alpine
LABEL name=ddns-go
LABEL url=https://github.com/gaoyaxuan/ddns-go
RUN apk add --no-cache curl grep tzdata

WORKDIR /app
COPY ddns-go /app/
ENV TZ=Asia/Shanghai
EXPOSE 9876
ENTRYPOINT ["/app/ddns-go"]
CMD ["-l", ":9876", "-f", "300"]

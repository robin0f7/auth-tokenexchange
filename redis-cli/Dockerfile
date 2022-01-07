FROM redis:6-bullseye
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && apt-get upgrade -y --no-install-recommends \
  && apt-get install -y \
      bash \
      inetutils-telnet \
      bind9-dnsutils \
      curl

COPY entrypoint.sh /redis-cli/
WORKDIR /redis-cli
ENV PATH=/usr/local/bin:$PATH
ENTRYPOINT ["/redis-cli/entrypoint.sh"]

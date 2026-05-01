FROM debian:bookworm-slim

ARG TARGETARCH
ARG NUCLEI_VERSION=3.8.0
ARG HTTPX_VERSION=1.9.0
ARG NAABU_VERSION=2.6.0

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/scanner-data
ENV SCANNER_HOST=0.0.0.0
ENV SCANNER_PORT=8788
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    nmap \
    python3 \
    tini \
    unzip \
  && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
  build_arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
  case "$build_arch" in \
    amd64) pd_arch=amd64 ;; \
    arm64) pd_arch=arm64 ;; \
    *) echo "Unsupported architecture: $build_arch" >&2; exit 1 ;; \
  esac; \
  install_pd_tool() { \
    tool="$1"; version="$2"; \
    url="https://github.com/projectdiscovery/${tool}/releases/download/v${version}/${tool}_${version}_linux_${pd_arch}.zip"; \
    tmp="/tmp/${tool}.zip"; \
    curl -fsSL "$url" -o "$tmp"; \
    unzip -p "$tmp" "$tool" > "/usr/local/bin/$tool"; \
    chmod 0755 "/usr/local/bin/$tool"; \
    rm -f "$tmp"; \
  }; \
  install_pd_tool nuclei "$NUCLEI_VERSION"; \
  install_pd_tool httpx "$HTTPX_VERSION"; \
  install_pd_tool naabu "$NAABU_VERSION"

WORKDIR /opt/scanner

COPY scanner_web.py copy_fail_check.sh copy_fail_mitigate.sh ./
COPY scripts/container-entrypoint.sh /usr/local/bin/scanner-entrypoint

RUN chmod 0755 /usr/local/bin/scanner-entrypoint \
  && chmod 0755 /opt/scanner/scanner_web.py /opt/scanner/copy_fail_check.sh /opt/scanner/copy_fail_mitigate.sh \
  && mkdir -p /opt/scanner/reports /scanner-data

VOLUME ["/opt/scanner/reports", "/scanner-data"]
EXPOSE 8788

ENTRYPOINT ["tini", "--", "scanner-entrypoint"]

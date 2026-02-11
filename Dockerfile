# ============================================================
# STAGE 1 — BUILDER
# ============================================================
FROM golang:1.25.3-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=local \
    GO111MODULE=on \
    GOWORK=off \
    GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    OUT=/out

WORKDIR /build

# ------------------------------------------------------------
# Build dependencies
# ------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl git unzip ca-certificates pkg-config \
    autoconf automake libtool make file \
    libssl-dev zlib1g-dev libnghttp2-dev libidn2-0-dev libpsl-dev \
    libkrb5-dev libssh2-1-dev \
    libreadline-dev libyaml-dev libffi-dev libbz2-dev libsqlite3-dev \
    liblzma-dev libgdbm-dev libnss3-dev libncurses-dev uuid-dev \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# libcurl custom
# ------------------------------------------------------------
RUN set -eux; \
    CURL_VER="$(curl -fsSL https://curl.se/download/ \
      | grep -Eo 'curl-[0-9]+\.[0-9]+\.[0-9]+\.tar\.xz' \
      | head -n1 | sed 's/curl-//;s/\.tar\.xz//')"; \
    curl -fsSL https://curl.se/download/curl-${CURL_VER}.tar.xz -o curl.tar.xz; \
    tar -xf curl.tar.xz; cd curl-${CURL_VER}; \
    ./configure --prefix=${OUT}/curl \
        --with-openssl \
        --with-nghttp2 \
        --enable-http --enable-ftp --enable-file --enable-tls-srp \
        --disable-static; \
    make -j$(nproc); make install; \
    ${OUT}/curl/bin/curl --version

ENV PKG_CONFIG_PATH=${OUT}/curl/lib/pkgconfig

# ------------------------------------------------------------
# Go tools
# ------------------------------------------------------------
COPY setup.sh .
RUN chmod +x setup.sh \
 && sed -i -E 's/(apt( |-)?get install -y[^#\n]*)\s+(golang(-go|-doc|-src)?)/\1/g' setup.sh \
 && bash -x setup.sh

# ------------------------------------------------------------
# Nuclei templates
# ------------------------------------------------------------
RUN install -d ${OUT}/nuclei-templates \
 && nuclei -silent -update-templates -ut ${OUT}/nuclei-templates || true

# ------------------------------------------------------------
# Ruby 
# ------------------------------------------------------------
ARG RUBY_PREFIX=/opt/darkmoon/ruby
ARG RUBY_VERSION=3.3.5

RUN git clone https://github.com/rbenv/ruby-build.git /tmp/ruby-build \
 && /tmp/ruby-build/install.sh \
 && ruby-build ${RUBY_VERSION} ${RUBY_PREFIX} \
 && rm -rf /tmp/ruby-build

# Ruby tools
COPY setup_ruby.sh /setup_ruby.sh
RUN chmod +x /setup_ruby.sh && /setup_ruby.sh

# ------------------------------------------------------------
# Python custom
# ------------------------------------------------------------
ARG PY_VER=3.12.6
ARG PY_PREFIX=/opt/darkmoon/python
RUN curl -fsSL https://www.python.org/ftp/python/${PY_VER}/Python-${PY_VER}.tgz -o python.tgz \
 && tar -xzf python.tgz \
 && cd Python-${PY_VER} \
 && ./configure --prefix=${PY_PREFIX} --enable-optimizations --with-ensurepip=install \
 && make -j$(nproc) && make install

# ------------------------------------------------------------
# Rust
# ------------------------------------------------------------
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
 && . "$HOME/.cargo/env"
ENV PATH="/root/.cargo/bin:${PATH}"

# ------------------------------------------------------------
# Python tooling
# ------------------------------------------------------------
COPY setup_py.sh /setup_py.sh
RUN chmod +x /setup_py.sh && /setup_py.sh

# ------------------------------------------------------------
# SecLists
# ------------------------------------------------------------
ARG SECLISTS_REF=master
RUN git -c http.version=HTTP/1.1 clone --depth=1 --branch ${SECLISTS_REF} \
      https://github.com/danielmiessler/SecLists.git ${OUT}/seclists \
 && rm -rf ${OUT}/seclists/.git

# ============================================================
# STAGE 2 — RUNTIME
# ============================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    DM_HOME=/opt/darkmoon

# ------------------------------------------------------------
# Runtime OS dependencies + Playwright Chromium deps
# ------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # base runtime
    ca-certificates tzdata bash dnsutils jq curl git \
    \
    # libs runtime générales
    libssl3 zlib1g libnghttp2-14 libidn2-0 libpsl5 \
    libkrb5-3 libssh2-1 libyaml-0-2 libreadline8 \
    libffi8 libgmp10 libncursesw6 libpcap0.8 \
    hydra snmp openssh-client inotify-tools \
    \
    # requis pour pip / wheels
    build-essential pkg-config libffi-dev libssl-dev \
    \
    # dépendances Chromium / Playwright
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libgtk-3-0 \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# Node.js + Playwright (stable project install)
# ------------------------------------------------------------
WORKDIR /opt/darkmoon

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && npm init -y \
 && npm install playwright \
 && npx playwright install chromium \
 && npm cache clean --force

# ------------------------------------------------------------
# Core artefacts copiés depuis builder
# ------------------------------------------------------------
COPY --from=builder /out /out
COPY --from=builder /opt/darkmoon /opt/darkmoon

# ------------------------------------------------------------
# Environment runtime
# ------------------------------------------------------------
ENV PATH="/opt/darkmoon/curl/bin:/opt/darkmoon/python/bin:/opt/darkmoon/ruby/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:/opt/darkmoon/curl/lib:/opt/darkmoon/python/lib:/opt/darkmoon/ruby/lib"

RUN ln -s /opt/darkmoon/python/bin/python3 /usr/local/bin/python \
 && ln -s /opt/darkmoon/python/bin/pip3 /usr/local/bin/pip

# ------------------------------------------------------------
# Wordlists & data
# ------------------------------------------------------------
RUN mkdir -p /usr/share/wordlists /usr/share/dirb \
 && ln -sfn /out/seclists /usr/share/seclists \
 && ln -sfn /usr/share/seclists /usr/share/wordlists/seclists \
 && ln -sfn /out/wordlists/dirb /usr/share/dirb/wordlists \
 && ln -sfn /usr/share/seclists ${DM_HOME}/seclists

ENV SECLISTS=/usr/share/seclists \
    NUCLEI_TEMPLATES=${DM_HOME}/nuclei-templates

# ------------------------------------------------------------
# Binary and wrapper installations
# ------------------------------------------------------------
RUN test -d /out/bin || { echo "ERROR: /out/bin directory not found"; exit 1; } \
 && test "$(ls -A /out/bin 2>/dev/null)" || { echo "ERROR: /out/bin is empty"; exit 1; }

RUN for bin in /out/bin/*; do \
      install -m 755 "$bin" "/usr/local/bin/$(basename "$bin")"; \
    done

# ------------------------------------------------------------
# Post-install validation minimale
# ------------------------------------------------------------
RUN command -v nuclei >/dev/null \
 && command -v finalrecon >/dev/null \
 && command -v node >/dev/null \
 && node -e "require('playwright')"

# ------------------------------------------------------------
# Nuclei bootstrap
# ------------------------------------------------------------
RUN mkdir -p /root/nuclei-templates \
 && cp -a ${NUCLEI_TEMPLATES}/. /root/nuclei-templates/ || true \
 && nuclei -tl >/dev/null 2>&1 || true

# ------------------------------------------------------------
# Hardening
# ------------------------------------------------------------
RUN apt-get purge -y login passwd libpam* gnupg* apt || true \
 && rm -rf /etc/apt /var/lib/apt /var/cache/apt

RUN mkdir -p /var/lib/dpkg \
 && : > /var/lib/dpkg/status \
 && rm -rf /var/lib/dpkg/info /var/lib/dpkg/updates

ENTRYPOINT ["bash"]
CMD ["-lc", "sleep infinity"]
# ============================================================
# STAGE 1 — BUILDER
# ============================================================
FROM golang:1.26-bookworm AS builder

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
# SecLists — sparse: only the files actually used by agents
# ------------------------------------------------------------
RUN install -d \
      ${OUT}/seclists/Discovery/Web-Content \
      ${OUT}/seclists/Passwords \
      ${OUT}/seclists/Fuzzing \
      ${OUT}/seclists/Discovery/DNS \
 && BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master" \
 && curl -fsSL --retry 3 "${BASE}/Discovery/Web-Content/common.txt" \
      -o ${OUT}/seclists/Discovery/Web-Content/common.txt \
 && curl -fsSL --retry 3 "${BASE}/Discovery/Web-Content/big.txt" \
      -o ${OUT}/seclists/Discovery/Web-Content/big.txt \
 && curl -fsSL --retry 3 "${BASE}/Discovery/Web-Content/raft-medium-words.txt" \
      -o ${OUT}/seclists/Discovery/Web-Content/raft-medium-words.txt \
 && curl -fsSL --retry 3 "${BASE}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt" \
      -o ${OUT}/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
 && curl -fsSL --retry 3 "${BASE}/Discovery/DNS/subdomains-top1million-5000.txt" \
      -o ${OUT}/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
 && curl -fsSL --retry 3 "${BASE}/Fuzzing/fuzz-Bo0oM.txt" \
      -o ${OUT}/seclists/Fuzzing/fuzz-Bo0oM.txt

# ============================================================
# STAGE 2 — CUDA DEVEL (GPU + CPU fallback)
# ============================================================
FROM nvidia/cuda:13.1.0-devel-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive \
    DM_HOME=/opt/darkmoon

# ------------------------------------------------------------
# Runtime OS dependencies
# ------------------------------------------------------------
RUN sed -i 's|http://archive.ubuntu.com|http://fr.archive.ubuntu.com|g' /etc/apt/sources.list \
 && sed -i 's|http://security.ubuntu.com|http://fr.archive.ubuntu.com|g' /etc/apt/sources.list \
 && apt-get update -o Acquire::Retries=3 \
 && apt-get install -y --no-install-recommends \
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
    \
    # OpenCL loader
    ocl-icd-libopencl1 \
    opencl-headers \
    \
    # CPU OpenCL backend (fallback)
    pocl-opencl-icd \
    \
    # tools
    clinfo \
    wget \
    xz-utils \
    p7zip-full \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# Install official hashcat (CUDA enabled build)
# ------------------------------------------------------------
RUN wget https://hashcat.net/files/hashcat-6.2.6.7z \
 && 7z x hashcat-6.2.6.7z \
 && mv hashcat-6.2.6 /opt/hashcat \
 && ln -sf /opt/hashcat/hashcat.bin /usr/local/bin/hashcat \
 && rm hashcat-6.2.6.7z

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

# ------------------------------------------------------------
# Full rockyou.txt (134 MB) — required for hash cracking
# SecLists only ships fragments; download the real one from
# the canonical GitHub release mirror and place it where
# tools (hashcat, john, hydra) expect it.
# ------------------------------------------------------------
RUN curl -fsSL --max-redirs 5 \
      "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
      -o /usr/share/wordlists/rockyou.txt \
 && ln -sf /usr/share/wordlists/rockyou.txt \
          /usr/share/seclists/Passwords/rockyou.txt \
 && echo "[OK] rockyou.txt $(wc -l < /usr/share/wordlists/rockyou.txt) lines"

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


COPY conf/entrypoint-darkmoon.sh /entrypoint-darkmoon.sh
RUN sed -i 's/\r$//' /entrypoint-darkmoon.sh \
 && chmod +x /entrypoint-darkmoon.sh

ENTRYPOINT ["/entrypoint-darkmoon.sh"]
CMD ["bash","-lc", "sleep infinity"]
FROM python:3.14-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        hydra \
        nmap \
        curl \
    		unzip \
    		git \
    		perl \
				libnet-ssleay-perl \
				libjson-perl \
				libio-socket-ssl-perl \
				libxml-writer-perl \
				libmime-base64-perl \
				libxml-libxml-perl \
				sshpass \
				openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/sullo/nikto/releases/download/2.6.0/nikto-main.zip -o /tmp/nikto.zip \
    && unzip /tmp/nikto.zip -d /tmp/nikto \
    && mv /tmp/nikto/nikto-main/program /opt/nikto \
    && rm -rf /tmp/nikto /tmp/nikto.zip \
    && chmod +x /opt/nikto/nikto.pl \
    && ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto

# hadolint ignore=DL3013
RUN python -m pip install --no-cache-dir "git+https://github.com/maurosoria/dirsearch.git"

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

COPY . attacker/
RUN uv sync --frozen --no-dev

RUN mkdir -p reports attacker/wordlists \
    && useradd -m -u 1000 attacker \
    && chown -R attacker:attacker /app

USER attacker

ENTRYPOINT ["python", "-m", "attacker"]
CMD ["--help"]

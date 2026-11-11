FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates chromium fonts-dejavu-core openbox novnc websockify \
       util-linux x11-utils x11vnc xvfb \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10002 --no-create-home --home-dir /profile browser \
    && install -d -m 0700 -o browser -g browser /profile
COPY policies.json /etc/chromium/policies/managed/job-bridge.json
COPY start.sh /usr/local/bin/job-bridge-browser
ENV HOME=/profile DISPLAY=:99 XDG_RUNTIME_DIR=/tmp/job-bridge-runtime
USER browser
CMD ["bash", "/usr/local/bin/job-bridge-browser"]

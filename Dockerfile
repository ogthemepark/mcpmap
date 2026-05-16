# Slim, multi-stage build for the mcpmap CLI.
#
# Uses editable install so the package can find data/ via its current
# Path(__file__) relative lookup (data/remediations.yaml, fingerprints.yaml,
# cves.yaml, shodan_filters.json). The final image is ~140 MB.
#
# Build:  docker build -t mcpmap .
# Run:    docker run --rm -v "$PWD":/workspace mcpmap scan <target> --out /workspace/scan.json
# Help:   docker run --rm mcpmap --help

FROM python:3.11-slim AS base

RUN useradd -m -u 1000 mcpmap

WORKDIR /opt/mcpmap

COPY --chown=mcpmap:mcpmap pyproject.toml README.md ./
COPY --chown=mcpmap:mcpmap src ./src
COPY --chown=mcpmap:mcpmap data ./data

RUN pip install --no-cache-dir -e . \
 && pip install --no-cache-dir 'shodan>=1.31'

USER mcpmap
WORKDIR /workspace

ENTRYPOINT ["mcpmap"]
CMD ["--help"]

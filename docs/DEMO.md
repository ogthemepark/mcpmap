# Demo: scan-the-lab end-to-end

A 90-second walkthrough you can record for the README GIF / LinkedIn post.

## 1. Boot the lab

```bash
cd testlab
docker compose up --build -d
cd ..
sleep 8  # let services initialize
```

## 2. Discover

```bash
mcpmap discover 127.0.0.1
```
Expected: ten rows, ports 8001–8010, source=active.

## 3. Fingerprint one

```bash
mcpmap fingerprint http://127.0.0.1:8010/mcp
```
Expected: `framelink-figma-mcp — framelink-figma-mcp 0.0.5`.

## 4. Audit one

```bash
mcpmap audit http://127.0.0.1:8004/mcp
```
Expected: POISON-001 finding (the `<IMPORTANT>` block in the description).

## 5. Full scan

```bash
mcpmap scan 127.0.0.1 --out scan.json
```
Expected: ~10 servers, ~10+ findings.

## 6. Render the map

```bash
mcpmap report scan.json --format html --out scan.html
open scan.html
```
Expected: a force-directed graph with 10 colored nodes. Click any node → side panel with findings.

## 7. Tear down

```bash
cd testlab && docker compose down && cd ..
```

## Recording

Use `asciinema rec demo.cast` for the terminal half, then a screen recorder for the HTML graph. Or capture both with `peek` / OBS. Trim to ≤2 min for LinkedIn.

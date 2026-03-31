$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not $env:WARP_FRONT_PORT) {
    $env:WARP_FRONT_PORT = "10899"
}

python scripts/generate_microwarp_compose.py

docker compose -f docker-compose.yml -f docker-compose.microwarp.generated.yml up -d

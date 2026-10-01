#!/usr/bin/env bash
# Runs the envelope-swap demo. Needs JDK 24+ (ML-KEM is native: JEP 496).
set -euo pipefail
cd "$(dirname "$0")"
exec java EnvelopeDemo.java

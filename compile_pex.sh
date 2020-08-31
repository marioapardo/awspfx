#!/usr/bin/env bash

# Create poetry environment
./setup_venv.sh

#
echo "---"
#

# Install PEX
poetry run pip install -U pip pex

#
echo "---"
#

# Compile Image
poetry run pex . --sources-directory=awspfx --entry-point=awspfx --requirement=requirements.txt --output-file=awspfx.pex

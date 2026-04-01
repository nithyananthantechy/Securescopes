#!/bin/bash
echo "Starting SecureScope by NiTechSpark..."
cd "$(dirname "$0")"
sudo python3 main.py web --port 8080

#!/bin/bash
set -e

echo "===== Darkmoon GPU Auto Detection ====="

if command -v nvidia-smi >/dev/null 2>&1; then
    if nvidia-smi >/dev/null 2>&1; then
        echo "GPU detected → CUDA mode enabled"
        export DM_GPU=1
    else
        echo "nvidia-smi present but no driver → CPU fallback"
        export DM_GPU=0
    fi
else
    echo "No NVIDIA GPU detected → CPU mode"
    export DM_GPU=0
fi

exec "$@"
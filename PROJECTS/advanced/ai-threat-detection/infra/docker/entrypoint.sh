#!/bin/sh
# ©AngelaMos | 2026
# entrypoint.sh

MODEL_DIR="${MODEL_DIR:-data/models}"
NGINX_LOG_PATH="${NGINX_LOG_PATH:-/var/log/nginx/access.log}"

for f in /var/log/nginx/access.log /var/log/nginx/error.log; do
    if [ -L "$f" ]; then
        rm -f "$f"
    fi
done

REQUIRED_FILES="ae.onnx rf.onnx if.onnx scaler.json threshold.json"

all_models_exist() {
    for f in $REQUIRED_FILES; do
        if [ ! -f "$MODEL_DIR/$f" ]; then
            return 1
        fi
    done
    return 0
}

if all_models_exist; then
    echo "Trained models found in $MODEL_DIR — skipping auto-train"
elif [ "$SKIP_AUTO_TRAIN" = "true" ]; then
    echo "SKIP_AUTO_TRAIN=true — starting in rules-only mode"
else
    echo "No ML models found in $MODEL_DIR — training with synthetic data..."
    echo "This takes ~1-2 minutes on first run. Models persist to the volume for future starts."
    python -m cli.main train \
        --synthetic-normal 2000 \
        --synthetic-attack 1000 \
        --output-dir "$MODEL_DIR" \
        --epochs 100 \
        --batch-size 256 2>&1

    if [ $? -eq 0 ]; then
        echo "Training complete — starting in hybrid (rules + ML) mode"
    else
        echo "WARNING: Training failed — starting in rules-only mode"
    fi
fi

exec "$@"

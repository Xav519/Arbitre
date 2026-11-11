# Model artifacts

Open-weight model files go here, and only after they are declared in `../model-lock.yaml` with a pinned revision and a SHA-256.

InnovaBank currently runs on managed Amazon Bedrock models only, so this directory is empty. The gate still runs on every push, and CI proves it works by generating a malicious pickle and checking that the scan rejects it.

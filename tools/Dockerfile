# Test bed for the Linux backend. The point is a real kernel with real
# Landlock and real seccomp; nothing here is part of the shipped package.
FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends libseccomp2 \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pytest hypothesis

WORKDIR /work
ENV PYTHONPATH=/work/src
ENV PYTHONDONTWRITEBYTECODE=1

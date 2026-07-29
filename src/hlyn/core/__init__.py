"""Enforcement backends.

One module per platform. Each exposes the same small surface, so the
orchestrator never branches on the operating system, and adding a backend is a
drop-in file rather than an edit to shared code.
"""

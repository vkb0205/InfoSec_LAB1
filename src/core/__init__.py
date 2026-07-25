"""Core vault package.

Day 2 owns vault initialization, unlock, and in-memory DEK management.  Shared
errors live in :mod:`src.errors` so this package remains independent of the CLI
or any optional web framework.
"""

# Secure LLM Gateway

A FastAPI-based secure gateway for LLM applications that inspects prompts and model responses, applies security policies, and blocks, redacts, or reviews unsafe interactions before they reach end users.

## Why this project matters

This project is designed to show practical engineering around LLM security rather than just model usage. It demonstrates how to build a gateway layer that treats prompts and responses as an attack surface, which is directly relevant to AI security, trust and safety, backend engineering, and platform roles.[1]

## Highlights

- Built as a FastAPI-based proxy for securing LLM interactions in a realistic application flow.
- Inspects requests and responses against security policies to reduce OWASP-style LLM risks.
- Blocks or sanitizes unsafe content instead of acting as a thin wrapper around a model API.
- Includes observability-oriented endpoints such as health and metrics to support production-style operations work.
- Shows a combination of infrastructure thinking, security controls, and product-minded API design aimed at real deployment concerns.[2]

## What this signals to recruiters

This repository is meant to signal the ability to work at the intersection of backend systems, AI infrastructure, and application security.[2] It is especially relevant for teams building LLM features, internal AI platforms, abuse prevention systems, API gateways, or trust-and-safety tooling.[1]

## Core capabilities

- Prompt inspection before model execution.
- Response inspection and policy enforcement after model execution.
- Security-oriented gateway behavior such as allow, block, sanitize, and review-style handling.
- Operational readiness through endpoint-level health and metrics support.

## Tech stack

- Python
- FastAPI
- YAML-based prompt configuration
- Middleware for request context, authentication, and rate limiting

The project is intentionally framed as a security-flavored backend system rather than a demo chatbot, which makes it stronger for AI security and systems-oriented roles.[2]

## What to look at first

- `/chat` for the main gateway behavior
- `/health` and `/metrics` for operational readiness
- Middleware and policy flow for request inspection and enforcement
- Prompt configuration for versioned system behavior

## Run locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open the docs at `http://127.0.0.1:8000/docs`.
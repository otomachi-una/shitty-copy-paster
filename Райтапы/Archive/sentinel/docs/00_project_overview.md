# Sentinel AML — Project Overview

Sentinel AML is a Go-based Attack-Defense CTF service for ForcAD. It models an AML investigation platform where future flags are stored in normal private investigation records, not in synthetic flag endpoints.

## Current Scope

Wave 01 establishes repository shape, process entrypoints, ForcAD layout, and validation gates only.

Implemented skeleton components:

- `aml-api` placeholder process.
- `aml-worker` placeholder process.
- `checkers/sentinel_aml` fail-closed checker placeholder.
- `sploits/sentinel_aml` documentation-only exploit placeholder.
- Validation scripts and tests.

## Runtime Shape

Future runtime components are:

- Go API service.
- Go worker service.
- PostgreSQL for durable state.
- Optional Redis or in-process queue if later ADRs approve it.

No product API, database schema, authentication, checker lifecycle behavior, planned vulnerability, exploit, or reference fix exists in Wave 01.

# Invoices service: threat pack

## Purpose

A small invoicing API used by two tenants. Each tenant's members read and revise their own invoices; nobody reads or changes
another tenant's.

## Trust boundaries

Requests arrive over HTTP with a session header that names the principal and the principal's tenant. The store is shared by all
tenants and is scoped by tenant on every access.

## Invariants

- TENANT-ISOLATION-001: a principal of one tenant cannot read or modify another tenant's invoice.
- AUTHN-REQUIRED-001: every invoice route requires an authenticated principal.

## Known controls

The session middleware authenticates every request before a handler runs. Handlers scope their store access by the principal's
tenant.

## Review priorities

Cross-tenant reads and writes first; then anything that reaches the store without the tenant scope.

# 01. Architecture Overview

## 1.1 Introduction
This project implements a Fine-Grained Authorization (FGA) system for a multi-tenant SaaS platform. It leverages **Open Policy Agent (OPA)** for decision-making and **OPAL (Open Policy Administration Layer)** for real-time policy and data synchronization. The enforcement point is the **APISIX API Gateway**.

## 1.2 System Components

The architecture consists of four main pillars:

### 1. Enforcement Point: APISIX API Gateway
*   **Role**: Intercepts all incoming HTTP traffic.
*   **Function**:
    *   **Authentication**: Uses the `openid-connect` plugin to authenticate users via an Identity Provider (IdP). It validates JWTs and extracts user information.
    *   **Context Injection**: Injects the user's identity (Email, Groups) into the `X-Userinfo` header (Base64 encoded) before forwarding the request to the upstream or the policy engine.
    *   **Authorization**: Uses the `opa` plugin to send the request context (Method, Path, Headers, IP) to the local OPA sidecar for a decision (Allow/Deny).

### 2. Decision Engine: OPA (Open Policy Agent)
*   **Role**: Running as a sidecar to APISIX (via OPAL Client).
*   **Function**:
    *   Receives `input` JSON from APISIX.
    *   Executes Rego policies (`policy.rego`, `inheritance.rego`) against the input and loaded data (`data.json`).
    *   Returns a JSON decision: `{"allow": true}` or `{"allow": false, "reason": "..."}`.
    *   **Performance**: Decisions are made locally in microseconds/milliseconds.

### 3. Synchronization Layer: OPAL (Server & Client)
*   **OPAL Server**:
    *   Watches a Git Repository for Policy changes (Rego files).
    *   Serves initial policy bundles to clients.
    *   Pushes real-time updates via WebSocket (Pub/Sub) when the Git repo changes.
*   **OPAL Client**:
    *   Runs alongside OPA.
    *   Subscribes to updates from OPAL Server.
    *   Downloads Policy Bundles and Data updates.
    *   Hot-reloads OPA without downtime.

### 4. Policy Manager (Python/Flask)
*   **Role**: Administrative UI and API.
*   **Function**:
    *   Provides a Dashboard to manage Organizations, Users, Departments, Groups, and Roles.
    *   Edits the `data.json` source of truth.
    *   Visualizes the Policy Hierarchy.
    *   Provides "Test Policy" tools to simulate OPA decisions and trace inheritance.

## 1.3 The Request Flow

1.  **Client Request**: User sends `GET /mail/inbox`.
2.  **APISIX (Auth)**: Validates Cookie/Token. Decodes User Info.
3.  **APISIX (Context)**: Adds header `X-Userinfo: eyJlbWFpbCI6...`.
4.  **APISIX (Authz)**: Sends request details to OPA.
5.  **OPA (Evaluate)**:
    *   Parses `X-Userinfo` to get `user_email`.
    *   Looks up User in `data.json`.
    *   Calculates **Effective Permissions** by merging:
        *   Global Defaults
        *   Organization Policy
        *   Department Policy
        *   Group Policies
        *   Role Policies (and Inherited Roles)
    *   Checks if the User has `read` permission for `/mail/inbox`.
    *   Checks if User's IP is Whitelisted.
6.  **OPA (Result)**: Returns `Allow` or `Deny`.
7.  **APISIX (Action)**: Forwards to backend (if Allow) or returns 403 Forbidden (if Deny).

## 1.4 Key Design Concepts

*   **Data-Driven Policy**: The logic is generic (`inheritance.rego`); the actual rules are data (`data.json`). This allows tenants to have completely different rules without changing code.
*   **Hierarchical Inheritance**: Policies cascade. Granular levels (User/Group) can override or extend broader levels (Org/Dept).
*   **Decoupled Architecture**: The Policy Manager manages data, Git stores history, OPAL syncs it, OPA executes it. No direct coupling between UI and Gateway.

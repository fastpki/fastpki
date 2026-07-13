# FastPKI

A lightweight, high-performance, and ultra-secure Public Key Infrastructure (PKI) designed for modern cloud-native, on-premise, and edge environments. **FastPKI** combines enterprise-grade security—including Post-Quantum Cryptography (PQC) and Hardware Security Module (HSM) support—with a tiny footprint and effortless management.

> ⚡ **Ultra-Lightweight & Blazing Fast:** Native code running at 2-4MB per binary with minimal resource footprint and multi-threaded throughput.

---

## 🚀 Key Features

### 💎 Simplicity & Deployment
* **One-Click Deployment:** Get a production-ready PKI environment up and running instantly.
* **Intuitive Web UI:** A beautiful, streamlined interface built for rapid configuration, live monitoring, and instant compliance auditing.
* **Zero-Downtime Maintenance:** Hassle-free backups, one-click restores, and completely uninterruptible updates.
* **Flexible Environments:** Deploy natively on-premise, in the cloud via VM services, or as highly orchestrated Kubernetes workloads.

### ⚡ Performance & Scalability
* **Micro Footprint:** Extremely optimized native code using just **2–4MB of RAM per binary**, making it perfect for edge devices and micro-containers.
* **Horizontal Scalability:** Multi-threaded performance built to scale horizontally across global clusters.
* **Autonomous Edge (Split-Brain Resilience):** Data centers function completely autonomously while disconnected. Databases automatically sync and reconcile conflicts seamlessly once connectivity is restored.

### 🔒 Enterprise-Grade Security
* **Client-Side Key Generation:** Secure "pull" approach where private keys are generated safely on the client side, eliminating the risk of server-side interception.
* **HSM Integration:** Native hardware security module (HSM) support to securely isolate and protect your Root and Sub-CA private keys.
* **Post-Quantum Ready (PQC):** Future-proofed with native support for state-of-the-art **ML-DSA** quantum-resistant algorithms.
* **AI-Readiness:** Fully supports the Model Context Protocol (**MCP**), enabling secure, structured AI integrations and automated agentic management.
* **Multi-CA & Multi-Tenant:** Architected from the ground up to securely host multiple isolated tenants and distinct CA hierarchies on a single cluster.
* **Granular RBAC:** Fine-grained Role-Based Access Control allowing you to delegate distinct permissions to operators, auditors, and automated API tokens.
* **Cryptographic Audit Logs:** Every single configuration change, certificate issuance, and revocation is permanently logged and tracked for comprehensive compliance auditing.

---

## 🛠 Supported Protocols & Auth

### Certificate Management
FastPKI acts as a universal adapter, natively supporting all standard certificate management protocols:
* **Enrollment:** ACME, SCEP, EST, CMP (v2 & v3), MS-XCEP, MS-WSTEP
* **Validation & Revocation:** OCSP, CRLs, and Directory Services

### Authentication Ecosystem
Integrate seamlessly with your existing identity providers using versatile authentication hooks:
* **Enterprise Auth:** LDAP, Kerberos, SAML, OAuth / OIDC
* **Local & Network Auth:** Secure local accounts and robust Certificate-Based authentication

---

## 📄 License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**. It is entirely free to use for personal, educational, and non-commercial projects. 

**Required Notice: Copyright (C) 2026 FastPKI <https://fastpki.com>**

For commercial usage rights, volume deployment, or enterprise support, please contact us to purchase a commercial license.

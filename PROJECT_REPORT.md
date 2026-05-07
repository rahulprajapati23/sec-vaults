# Project Report

<div align="center">

# Secure File Storage System with DAM-Style Audit Logging

**Project Report**

**Author:** Rahul Prajapati

**Date:** 06 May 2026

**Course / Subject:** Data Security System

</div>

---

## Abstract

This project presents a secure file storage and access-control platform designed for a Data Security System (DSS) course context. The system combines authenticated file handling, encrypted storage, controlled sharing, audit logging, and security monitoring into one working application. The goal is to demonstrate a practical implementation of secure digital data handling from the point of upload to download, sharing, and audit review.

The application uses a FastAPI backend and a React frontend, with authentication based on hashed passwords and JWT sessions. Uploaded files are stored in encrypted form, file metadata is preserved separately, and access to operations such as download, deletion, and sharing is restricted to the rightful owner. To support security analysis, the project also includes DAM-style auditing features inspired by enterprise data activity monitoring tools: structured logs, tamper-evident event records, anomaly detection, rate limiting, and alert-friendly event streams.

The report explains the project scope, research process, implementation findings, design choices, challenges, alternatives, and limitations. It also documents how the final system was validated locally through login, upload, download, registration, and audit-related tests. The result is a functional DSS-oriented application that demonstrates both secure engineering practices and operational monitoring.

<div style="page-break-after: always;"></div>

## Table of Contents

1. Introduction
2. Purpose of the Project
3. Problem Statement and Use Cases
4. Project Scope and Relevance to DSS
5. Research Process, Findings, and Analysis
6. System Design and Architecture
7. Deliverables
8. Challenges Faced and How They Were Addressed
9. Alternatives Available in the Market
10. Why This Project Idea Is Better
11. Advantages and Limitations
12. Individual Work Summary
13. Conclusion
14. References
15. Appendix

<div style="page-break-after: always;"></div>

## 1. Introduction

Data security is no longer limited to storing passwords safely or blocking unauthorized users. Modern systems must protect data during storage, transfer, sharing, and auditing. A secure file storage system therefore needs multiple layers of protection: authentication, authorization, encryption, logging, monitoring, and recovery-oriented design.

This project was developed as a secure digital data management solution that addresses those layers in a practical, working implementation. The system lets users create accounts, log in, upload files, view their own files, download only what they are allowed to access, and share content using controlled links. On top of the normal file-storage features, the project records structured security events and supports tamper-evident auditing.

The project is relevant to a DSS course because it demonstrates how a digital system can protect information assets while remaining usable. Rather than focusing only on theory, it combines research-driven design with implementation, testing, and deployment considerations. The final application shows how a secure platform can be built using current web technologies while keeping the data model and security flow understandable.

## 2. Purpose of the Project

The purpose of this project is to build a working secure data platform that demonstrates the major concepts of a DSS-style system:

- secure user authentication and session control,
- encrypted file storage,
- access-restricted retrieval and sharing,
- security monitoring and audit logging,
- operational response support through alerts and event review,
- and reliable deployment for local and cloud-based use.

The project also serves as a learning exercise in secure digital engineering. It shows how frontend and backend layers interact, how a database should be structured for metadata and audit records, and how security controls can be layered without making the user experience unusable.

In academic terms, the project is meant to demonstrate a working knowledge of secure system design: identifying the threat surface, narrowing access, preserving evidence, and maintaining integrity of stored records.

## 3. Problem Statement and Use Cases

### Problem Statement

Many file sharing and storage platforms prioritize convenience, but do not clearly expose how files are protected or how actions are audited. Users often have no visibility into where the file is stored, how access is controlled, or whether abnormal behavior is logged. In small or student-built systems, security controls are frequently missing or separated into unrelated modules, which makes the platform easy to demonstrate but weak in realistic use.

This project addresses the need for a compact yet secure system that can:

- authenticate users safely,
- store uploaded files without exposing raw content,
- restrict access to owners and valid share recipients,
- create traceable events for security analysis,
- and remain usable in a local or cloud environment.

### Use Cases

The application is designed around practical use cases:

1. A user creates an account and signs in.
2. A user uploads a file and stores it securely.
3. A user views a list of their own files.
4. A user downloads a file if the file is still valid and accessible.
5. A user shares a file through a controlled access link.
6. An administrator reviews audit events for suspicious access or brute-force behavior.
7. The system records authentication events, file events, and alert-worthy events for later review.

These use cases reflect the core objective of a DSS: protect data while still allowing legitimate operations.

## 4. Project Scope and Relevance to DSS

The scope of this project covers secure file storage and security event monitoring at the application level. It does not attempt to solve every enterprise security problem, but it does implement the essential mechanisms that make a digital system defensible and auditable.

### Scope Covered

- Registration and login using hashed credentials.
- Session management using JWT-based authentication.
- File uploads and downloads controlled by ownership.
- Encrypted file storage.
- Metadata storage in a database.
- Controlled file sharing through token-based links.
- Audit logging for login and file activity.
- Basic security telemetry such as rate limiting and alert generation.

### Why It Is Relevant to DSS

A DSS is expected to manage data securely and support decision-making or control actions based on system state. This project fits that idea because it captures security events, preserves records, and makes file access decisions based on identity and policy. The event logs can be used for investigation or operational monitoring, which is a key DSS theme.

The project is also relevant because it demonstrates the relationship between design and control:

- the frontend provides user interactions,
- the backend enforces rules,
- the database stores state and evidence,
- and the audit subsystem turns activity into reviewable security information.

## 5. Research Process, Findings, and Analysis

### Research Process

The project was developed through a process of iterative research and implementation. The main steps were:

1. Identify the security and usability requirements for a file platform.
2. Study modern web backend and frontend frameworks suitable for rapid development.
3. Review authentication, encryption, and audit logging practices.
4. Build the core backend first to define data flow and policy enforcement.
5. Build the frontend to match the API contract.
6. Test critical flows such as login, upload, list, download, share, and logout.
7. Observe runtime failures and adjust the design for deployment reliability.

The research was not purely academic. It included practical investigation of the existing codebase, runtime logs, and deployment behavior. This helped reveal how a real system behaves under missing environment variables, absent directories, placeholder configuration values, and database-specific SQL syntax.

### Findings

Several findings emerged during development and testing:

- Security behavior must be enforced in the backend, not just displayed in the UI.
- A secure file application needs separate handling for metadata and file content.
- SQLite and PostgreSQL behave differently, especially in parameter binding and schema behavior.
- A missing configuration value can prevent the entire app from starting if it is required too early.
- Mounting static assets must be conditional or guaranteed in deployment.
- Frontend and backend API contracts must remain synchronized or users will see 404 and 500 errors.

### Analysis

The most important analysis result was that the system needed to be resilient in development and deployment environments. The project started as a more enterprise-oriented design, but local reliability required practical fallback behavior. For example, when PostgreSQL-specific code caused failures in the local environment, the backend was adjusted to support SQLite as a fallback. That design change did not reduce the project’s security goals; it improved testability and made the system easier to demonstrate.

Another key analysis point was that the audit layer is not just a logging feature. In this project, audit events are structured, attributed, and suitable for future use by a monitoring or SIEM-like consumer. That makes the project closer to a real DSS than a simple file uploader.

## 6. System Design and Architecture

The system is organized into frontend, backend, database, and storage layers.

### Frontend Layer

The frontend is built using React and TypeScript. It provides pages for login, registration, dashboard browsing, file views, settings, and related workflows. The frontend talks to the backend through an API service layer.

### Backend Layer

The backend is implemented with FastAPI. It handles authentication, file handling, DAM event generation, system status checks, and other route logic. Security-related decisions happen here so the frontend cannot bypass policy.

### Database Layer

The database stores user accounts, file metadata, activity logs, and audit records. It is designed so that the application can track what happened without storing sensitive file contents directly in the database.

### Storage Layer

Uploaded files are stored separately from metadata. The storage layer keeps encrypted or controlled blobs on disk so file contents are not exposed as plain data.

### High-Level Flow

1. User logs in.
2. Backend issues a session token.
3. User uploads a file.
4. Backend stores the file and metadata.
5. Backend records audit and event information.
6. User can list or download files according to permissions.
7. Security events can be reviewed later.

### Architecture Summary

The architecture follows the principle of separation of concerns. Authentication, file operations, audit logging, and alerting are implemented as distinct services. This makes the codebase easier to understand and reduces accidental coupling between security logic and UI logic.

## 7. Deliverables

The major deliverables of the project are:

- A working secure file storage web application.
- User registration and login flow.
- File upload, listing, download, deletion, and sharing support.
- Tamper-evident audit/event logging.
- Basic security monitoring and alerting infrastructure.
- Frontend and backend codebase with deployment support.
- Docker-based deployment configuration.
- Documentation for usage and architecture.

These deliverables satisfy the assignment expectation of including diagrams, structure, design, and a project write-up.

## 8. Challenges Faced and How They Were Addressed

### 1. Database Compatibility

One challenge was that local development and deployment used different database assumptions. PostgreSQL-specific queries or placeholders caused errors in SQLite. This was solved by aligning SQL syntax with the active database connection and by keeping the local environment functional.

### 2. Missing Configuration Values

Another issue was startup failure when `MASTER_KEY` or other environment values were missing or malformed. This was addressed by improving configuration parsing and making the application more resilient to placeholder deployment values.

### 3. Missing Static Assets Directory

The app attempted to mount a static directory even when the directory was absent in the runtime image. That caused startup crashes. The fix was to make the mount conditional so the application only serves static assets when the directory exists.

### 4. Frontend-Backend API Drift

At multiple points, the frontend expected routes that the backend had not yet exposed. This caused 404 responses and broken screens. The fix was to align the route list and remove or replace stale UI references.

### 5. Unused Code and Build Errors

TypeScript build checks surfaced unused imports after UI changes. These were fixed by removing the stale code and rebuilding the frontend.

### 6. User Experience vs Security Tradeoff

A security-heavy design can easily become hard to demo. The project addressed this by keeping the security controls real but practical, using clear UI states and a stable local fallback configuration.

## 9. Alternatives Available in the Market

Several market alternatives exist for secure file storage and controlled sharing:

- Google Drive with enterprise sharing controls.
- Dropbox Business with file permissions and team management.
- Microsoft OneDrive / SharePoint.
- Box with enterprise governance features.
- Specialized DAM / SIEM platforms such as IBM Guardium and Splunk integrations.

These tools are strong, mature, and production-ready. However, they are not suitable as a student project demonstration because they are either closed-source, too broad, or too complex to explain at the implementation level in an academic report.

## 10. Why This Project Idea Is Better Than Those Alternatives

This project is better for the purpose of a DSS assignment because it is educational, inspectable, and purpose-built to demonstrate design decisions.

### Reasons

- The entire data flow is visible from UI to backend to storage.
- Security controls are implemented in source code, not hidden behind a hosted product.
- The project combines file security with audit logging, which is more instructive than a simple file manager.
- It can be run locally and inspected by instructors.
- The architecture can be explained clearly in a report and in viva questions.

Commercial tools may be stronger operationally, but they do not show the design process. This project is more suitable for learning because it exposes the decisions, tradeoffs, and control points that matter in a DSS system.

## 11. Advantages and Limitations

### Advantages

- Secure account-based access.
- Encrypted file handling.
- Ownership-based authorization.
- Controlled sharing workflow.
- Structured audit and security event logging.
- Clear separation of frontend, backend, and data storage.
- Deployment-ready structure with Docker support.
- Local development fallback for easier testing.

### Limitations

- The project is not a full enterprise DLP platform.
- Some alerting and SIEM integrations are intentionally minimal for demo purposes.
- File encryption and storage logic are practical but not as feature-complete as large commercial platforms.
- Cloud environment configuration still requires careful setup of secrets and deployment variables.
- Production hardening such as full key rotation, centralized secrets management, and formal incident response is outside the current scope.

## 12. Individual Work Summary

This work was completed as an individual student project. The implementation, debugging, deployment fixes, documentation, and report preparation were handled in one codebase by one contributor. The benefit of individual work is that the project remains internally consistent: the architecture, UI flow, backend policy, and audit design all match the same implementation decisions.

For an individual academic submission, this also has an advantage in presentation. The student can clearly explain the problem, the design choices, the implementation steps, the failures encountered, and the final working state.

## 13. Conclusion

This project demonstrates a complete small-scale secure file storage platform with DSS relevance. It shows how secure authentication, encrypted storage, controlled sharing, and audit logging can be combined into a single working application. The system is not only functional, but also suitable for teaching and evaluation because the code reveals how policy is enforced and how events are captured.

The project also highlights an important practical lesson: security software must be stable in real deployment conditions. Missing directories, environment variables, or database-specific SQL syntax can break an otherwise correct design. By identifying and fixing these issues, the project became more robust and more realistic.

Overall, the work fulfills the assignment goal of demonstrating secure digital system design, research-driven implementation, and critical analysis of alternatives and limitations.

<div style="page-break-after: always;"></div>

## 14. References

1. FastAPI Documentation. https://fastapi.tiangolo.com/  
   Accessed 06 May 2026.

2. React Documentation. https://react.dev/  
   Accessed 06 May 2026.

3. TypeScript Handbook. https://www.typescriptlang.org/docs/  
   Accessed 06 May 2026.

4. Uvicorn Documentation. https://www.uvicorn.org/  
   Accessed 06 May 2026.

5. SQLite Documentation. https://www.sqlite.org/docs.html  
   Accessed 06 May 2026.

6. Python `hashlib` and `hmac` Standard Library Documentation. https://docs.python.org/3/library/hashlib.html and https://docs.python.org/3/library/hmac.html  
   Accessed 06 May 2026.

7. JSON Web Token (JWT) Overview. https://jwt.io/introduction  
   Accessed 06 May 2026.

8. NIST Recommendations for Authenticated Encryption (AES-GCM context). https://csrc.nist.gov/  
   Accessed 06 May 2026.

9. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/  
   Accessed 06 May 2026.

10. Docker Documentation. https://docs.docker.com/  
    Accessed 06 May 2026.

## 15. Appendix

### Appendix A: Core Modules

- `backend/app/main.py` - application entry point and startup lifecycle.
- `backend/app/routes/auth.py` - registration, login, logout, and account checks.
- `backend/app/routes/files.py` - file upload, listing, download, delete, and share flow.
- `backend/app/routes/dam.py` - DAM event visibility endpoints.
- `backend/app/services/audit.py` - structured logger for security events.
- `backend/app/config.py` - environment and secret loading.
- `frontend/src/features/auth/RegisterPage.tsx` - registration UI.
- `frontend/src/features/settings/SettingsPage.tsx` - security settings UI.

### Appendix B: Event Flow Summary

```text
User action -> backend route -> validation -> database update -> audit event -> optional alert/stream
```

### Appendix C: Short Design Notes

- Keep authentication logic server-side.
- Keep file metadata separate from file content.
- Keep logs structured and attributed.
- Make deployment failure modes visible and fixable.
- Prefer small, testable control points over hidden logic.

### Appendix D: Sample Validation Results

- Login endpoint tested successfully.
- File upload and listing tested successfully.
- WebSocket alert heartbeat tested successfully.
- Registration endpoint tested successfully after SQL placeholder fix.
- Frontend production build tested successfully.

---

**End of Report**

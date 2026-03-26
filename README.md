# Auth Service

![Java](https://img.shields.io/badge/Java-21-orange?style=for-the-badge&logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.6-green?style=for-the-badge&logo=springboot)
![Spring Security](https://img.shields.io/badge/Spring%20Security-gray?style=for-the-badge&logo=springsecurity)
![OAuth2](https://img.shields.io/badge/OAuth2-blue?style=for-the-badge)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-blue?style=for-the-badge&logo=postgresql)
![JPA](https://img.shields.io/badge/Spring%20Data%20JPA-Hibernate-green?style=for-the-badge&logo=hibernate)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge)

> Part of the **contest-manager** platform — responsible for user identity, authentication, and secure access.

---

## Overview

The Auth Service is the **source of truth for user identities**.

It handles:
- OAuth2 Social Login (Google, GitHub)
- User profile creation and persistence
- JWT generation
- Providing global UUIDs used across all microservices

> Unlike other services, this is an **edge service** and does **not use Kafka**.

---

## Responsibilities

- Authenticate users via OAuth2 providers
- Maintain authoritative `users` table
- Issue stateless JWTs
- Provide authenticated user profile data

---

## Platform Role

```
        ┌──────────────┐
        │ Auth Service │
        │ (Port 8081)  │
        └──────┬───────┘
               │ issues JWT
               ▼
        ┌──────────────┐
        │ API Gateway  │
        │ (Port 8080)  │
        └──────┬───────┘
               │ validates & forwards X-User-Id
        ┌──────┴──────────────────┐
        ▼                         ▼
 Contest Service       Leaderboard Service
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3.3.6 |
| Security | Spring Security, Spring OAuth2 Client |
| Tokens | JJWT |
| Database | PostgreSQL |
| ORM | Spring Data JPA / Hibernate |
| Build | Maven |

---

## Database Schema

### `users`

| Column | Type | Description |
|---|---|---|
| `id` | `UUID` PK | Global User ID |
| `email` | `VARCHAR` | User email |
| `name` | `VARCHAR` | Display name |
| `provider` | `VARCHAR` | `google` / `github` |
| `provider_id` | `VARCHAR` | OAuth provider ID |
| `created_at` | `TIMESTAMP` | Account creation time |

**Unique Constraints:**
- `(email)`
- `(provider, provider_id)`

---

## Authentication Flow

```
1. Client calls:       GET /oauth2/authorization/{provider}
                              │
2. Redirect to:        OAuth Provider (Google / GitHub)
                              │
3. User authenticates with provider
                              │
4. Provider redirects: GET /login/oauth2/code/{provider}
                              │
5. Auth Service:       Fetches user details → Upserts into DB
                              │
6. JWT is generated
                              │
7. Redirect to frontend with JWT in URL or HttpOnly cookie
```

---

## REST API

### `GET /oauth2/authorization/{provider}`

Triggers the OAuth2 login flow.

**Supported providers:**

| Provider | Value |
|---|---|
| Google | `google` |
| GitHub | `github` |

---

### `GET /api/auth/me`

Returns the currently authenticated user's profile.

**Headers:**

```
Authorization: Bearer <JWT>
```

**Response:** User profile object (id, email, name, provider, createdAt)

---

## Configuration

```yaml
server:
  port: 8081

spring:
  application:
    name: auth-service

  datasource:
    url: jdbc:postgresql://localhost:5432/auth_db
    username: postgres
    password: your_password

  jpa:
    hibernate:
      ddl-auto: update

  security:
    oauth2:
      client:
        registration:

          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: email, profile
            redirect-uri: "{baseUrl}/login/oauth2/code/google"

          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope: read:user, user:email
            redirect-uri: "{baseUrl}/login/oauth2/code/github"

        provider:
          github:
            authorization-uri: https://github.com/login/oauth/authorize
            token-uri: https://github.com/login/oauth/access_token
            user-info-uri: https://api.github.com/user
            user-name-attribute: id

jwt:
  secret: your_base64_secret_key
  expiration: 86400000  # 24 hours in milliseconds
```

---

## Running Locally

### 1. Create the Database

```sql
CREATE DATABASE auth_db;
```

### 2. Set Environment Variables

```bash
export GOOGLE_CLIENT_ID=your_google_client_id
export GOOGLE_CLIENT_SECRET=your_google_client_secret

export GITHUB_CLIENT_ID=your_github_client_id
export GITHUB_CLIENT_SECRET=your_github_client_secret
```

### 3. Run the Service

```bash
mvn spring-boot:run
```

The service will be available at `http://localhost:8081`.

---

## Key Design Decisions

### Why OAuth2 instead of passwords?

- No password storage or hashing required
- Eliminates credential-based attack surface
- Faster user onboarding via trusted identity providers

### Why JWT instead of sessions?

- Stateless authentication — no server-side session store
- No database lookup required per request
- Works seamlessly across microservices

### Why UUID for user IDs?

- Prevents ID enumeration attacks
- Globally unique across all services without central coordination
- Safe to expose in URLs and tokens

---

## Project Structure

```
auth-service/
├── config/          # Security and OAuth2 configuration
├── controller/      # REST API endpoints
├── service/         # Business logic
├── repository/      # JPA repositories
├── entity/          # JPA entities (User)
├── security/        # JWT filter, OAuth2 handlers
└── dto/             # Request/response objects
```

---

## Related Services

| Service | Description |
|---|---|
| API Gateway | Validates JWTs and forwards `X-User-Id` header |
| [Contest Service](https://github.com/Prashanth291/contest-service) | Consumes user identity for contest management |
| [Leaderboard Service](https://github.com/Prashanth291/leaderboard-service) | Consumes user identity for rankings |

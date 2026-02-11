# 🔐 Authentication & Authorization System

A comprehensive, production-ready authentication and authorization system built with Node.js, Express, TypeScript, and PostgreSQL. This system provides secure user authentication, role-based access control (RBAC), permission management, and session management.

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Database Schema](#-database-schema)
- [API Endpoints](#-api-endpoints)
- [Authentication Flow](#-authentication-flow)
- [Getting Started](#-getting-started)
- [Environment Variables](#-environment-variables)
- [Usage Examples](#-usage-examples)
- [Security Features](#-security-features)
- [Future Enhancements](#-future-enhancements)

## ✨ Features

### 🔑 Authentication
- **User Registration** - Secure user signup with email validation
- **User Login** - JWT-based authentication with access and refresh tokens
- **Token Refresh** - Automatic token renewal without re-authentication
- **User Logout** - Secure session invalidation
- **Password Management** - Secure password hashing with bcrypt (12 salt rounds)
- **Session Management** - Track and manage user sessions with IP and User-Agent

### 👥 User Management
- **Profile Management** - Get and update user profile information
- **Extended Profile** - Manage bio, contact info, social links, and preferences
- **Password Change** - Change password with current password verification
- **Account Deactivation** - Users can deactivate their own accounts
- **Account Deletion** - Permanent account deletion with password confirmation
- **Session Management** - View and revoke active sessions

### 🛡️ Authorization
- **Role-Based Access Control (RBAC)** - Flexible role assignment system
- **Permission-Based Authorization** - Granular permission management
- **Role-Permission Mapping** - Assign permissions to roles
- **Multi-Role Support** - Users can have multiple roles
- **Middleware Protection** - Express middleware for route protection

### 👨‍💼 Admin Features
- **User Management** - List, search, activate/deactivate, and delete users
- **Role Management** - Create, update, and delete roles
- **Permission Management** - Create and manage permissions
- **User Role Assignment** - Assign/remove roles from users
- **Role Permission Assignment** - Assign/remove permissions from roles
- **Session Monitoring** - View and revoke user sessions

## 🛠️ Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Language**: TypeScript
- **Database**: PostgreSQL
- **ORM**: Prisma
- **Authentication**: JWT (jsonwebtoken)
- **Password Hashing**: bcrypt
- **Environment Variables**: dotenv

## 📁 Project Structure
auth-system/
├── prisma/
│ ├── schema.prisma # Database schema definition
│ └── migrations/ # Database migrations
├── src/
│ ├── config/
│ │ └── db.ts # Prisma client configuration
│ ├── controllers/
│ │ ├── auth-controller.ts # Authentication endpoints
│ │ ├── user-controller.ts # User management endpoints
│ │ └── admin-controller.ts # Admin endpoints
│ ├── middlewares/
│ │ └── jwt.ts # JWT authentication & authorization middleware
│ ├── routes/
│ │ ├── auth-routes.ts # Authentication routes
│ │ ├── user-routes.ts # User routes
│ │ ├── admin-routes.ts # Admin routes
│ │ └── index.ts # Route aggregator
│ ├── services/
│ │ └── auth-services.ts # Business logic layer
│ ├── types/
│ │ └── express/
│ │ └── index.d.ts # TypeScript type definitions
│ ├── scripts/
│ │ └── seed.ts # Database seeding script
│ ├── app.ts # Express app configuration
│ └── server.ts # Server entry point
├── package.json
├── tsconfig.json
└── README.md


## 🗄️ Database Schema

### Core Models

#### User
- Basic user information (email, username, firstName, lastName)
- Authentication fields (password, isVerified, isActive, lastLoginAt)
- Relationships: roles, sessions, profile, password resets, email verifications

#### Role
- Role name and description
- Relationships: users (many-to-many), permissions (many-to-many)

#### Permission
- Permission name, description, resource, and action
- Format: `resource:action` (e.g., `users:read`, `admin:access`)

#### Session
- Session token, expiration, IP address, User-Agent
- Tracks active user sessions

#### UserProfile
- Extended user information (bio, contact info, social links, preferences)

### Relationships

- **User ↔ Role**: Many-to-Many (UserRole junction table)
- **Role ↔ Permission**: Many-to-Many (RolePermission junction table)
- **User → Session**: One-to-Many
- **User → UserProfile**: One-to-One

## 🌐 API Endpoints

### Authentication Routes (`/api/v1/auth`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/signup` | Register a new user | No |
| POST | `/login` | User login | No |
| POST | `/refresh` | Refresh access token | No (refresh token) |
| POST | `/logout` | User logout | No (refresh token) |

### User Routes (`/api/v1/user`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/profile` | Get user profile | Yes |
| PATCH | `/update` | Update basic user info | Yes |
| PATCH | `/profile` | Update extended profile | Yes |
| POST | `/change-password` | Change password | Yes |
| GET | `/sessions` | Get user sessions | Yes |
| DELETE | `/sessions/:sessionId` | Revoke specific session | Yes |
| DELETE | `/sessions` | Revoke all sessions | Yes |
| POST | `/deactivate` | Deactivate account | Yes |
| DELETE | `/account` | Delete account | Yes |

### Admin Routes (`/api/v1/admin`)

#### User Management
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/users` | Get all users (paginated) | Admin |
| PATCH | `/users/:id/status` | Toggle user active status | Admin |
| GET | `/users/:id/sessions` | Get user sessions | Admin |
| DELETE | `/users/:id/sessions` | Revoke user sessions | Admin |
| DELETE | `/users/:id` | Delete user | Admin |

#### Role Management
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/roles` | Get all roles | Admin |
| POST | `/roles` | Create role | Admin |
| PUT | `/roles/:id` | Update role | Admin |
| DELETE | `/roles/:id` | Delete role | Admin |

#### Permission Management
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/permissions` | Get all permissions | Admin |
| POST | `/permissions` | Create permission | Admin |

#### Role-Permission Management
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/roles/:roleId/permissions` | Get role permissions | Admin |
| POST | `/roles/:roleId/permissions` | Assign permission to role | Admin |
| DELETE | `/roles/:roleId/permissions/:permissionId` | Remove permission from role | Admin |

#### User Role Management
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/users/:id/roles` | Get user roles | Admin |
| PUT | `/users/:id/roles` | Assign role to user | Admin |
| DELETE | `/users/:id/roles/:roleId` | Remove role from user | Admin |

## 🔄 Authentication Flow

### 1. Registration Flow
User → POST /auth/signup → Create User → Return User Info


### 2. Login Flow
User → POST /auth/login → Verify Credentials → Generate Tokens → Create Session → Return Tokens

### 3. Access Protected Route
Request → JWT Middleware → Verify Token → Check User Status → Attach User to Request → Route Handler

### 4. Token Refresh Flow
Request → Verify Refresh Token → Check Session → Generate New Tokens → Update Session → Return New Tokens

### 5. Logout Flow
Request → Extract Refresh Token → Delete Session → Return Success

## 🔧 Environment Variables

Create a `.env` file using `.env.example` as a template.

Required:
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_ACCESS_SECRET` - Secret for access tokens
- `JWT_REFRESH_SECRET` - Secret for refresh tokens

Optional (with defaults):
- `PORT` (default: 3002)
- `NODE_ENV` (default: development)
- `APP_URL` (default: http://localhost:3002)
- `JWT_ACCESS_EXPIRY` (default: 15m)
- `JWT_REFRESH_EXPIRY` (default: 7d)

Email:
- `EMAIL_PROVIDER` - `ethereal` for dev/testing, `smtp` for production
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` - required if `EMAIL_PROVIDER=smtp`


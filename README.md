# Calendar Tool

A production-ready calendar management system that uses a Model Context Protocol (MCP) service to interact with Google Calendar. The system provides intelligent calendar management through natural language interactions, with support for both AWS cloud deployment and local development environments.

## Overview

The Calendar Tool consists of three main components:

1. **Calendar Agent** - An intelligent agent that processes user requests and coordinates with the MCP service
2. **Calendar MCP** - A Model Context Protocol service that provides Google Calendar integration tools
3. **Calendar Agent API** - An API gateway layer that handles client requests (bearer token) and Slack bot integration

## Architecture

### AWS Cloud Deployment

The system is designed to run on AWS using the following services:

- **AWS Lambda** - Serverless compute for all components
- **API Gateway** - HTTP API endpoints with mTLS support and custom domain integration
- **AWS Systems Manager Parameter Store** - Secure configuration and secrets management
- **IAM** - Access control and policy enforcement
- **CloudWatch** - Logging and monitoring
- **S3** - Certificate truststore storage for mTLS
- **AWS Certificate Manager (ACM)** - SSL/TLS certificate management with DNS integration
- **Redis** - Caching for MCP tool discovery and token storage

### Local Development

The system can also run locally using:

- **FastAPI** - Local HTTP server for all components
- **Self-Signed Certificates** - Generated via the certificate manager for mTLS testing
- **Redis** - For caching and token storage

### Security Features

The system implements multiple layers of security:

- **Mutual TLS (mTLS)** - Client certificates for secure MCP communication
- **HMAC Signatures** - Request authentication using shared secrets
- **Fernet Encryption** - Token encryption for sensitive data storage
- **IAM Policies** - AWS IAM role-based access control
- **Google OAuth 2.0** - Secure authentication with Google Calendar
- **Bearer Token Authentication** - For client API access
- **Slack Signature Verification** - For Slack bot integration with user, channel, and bot authorization

## Components

### Calendar Agent

The main agent that processes user queries using an LLM (Large Language Model) and coordinates with the MCP service to interact with Google Calendar. The system uses **OpenAI GPT-5-mini** as its NLP model for understanding natural language requests and generating appropriate responses.

The agent architecture is designed to be easily extensible for different LLM models - the LLM integration is abstracted through a service layer, allowing developers to swap in different language models as needed. Currently GPT 5 models are supported.

The agent:

- Processes natural language calendar requests
- Discovers available MCP tools dynamically
- Renders calendar information in human-readable format
- Handles errors and authentication issues gracefully

### Calendar MCP Service

A Model Context Protocol service that provides Google Calendar integration. It exposes two main tools:

1. **FreeBusy Tool** - Checks calendar availability for a given time range
2. **Create Event Tool** - Creates calendar events with specified details

The MCP service handles:
- Google OAuth token management (encrypted storage in Redis)
- HMAC signature verification for agent requests
- Token refresh and error handling

### Calendar Agent API

An API gateway layer that provides two access methods:

1. **Client API** - Accepts requests with bearer token authentication
2. **Slack Bot Integration** - Handles Slack events with:
   - Slack signature verification
   - User authorization (allowed users list)
   - Channel authorization (allowed channels list)
   - Bot authorization (allowed bot IDs)
   - Initial Slack "Challenge" response

### Google OAuth Redirect Server

A separate service that handles the OAuth flow for linking Google accounts to the MCP service. Users can:

- Start the OAuth flow through a configured redirect URI
- Grant permissions for pre-configured Google Calendar scopes
- Complete authentication and encrypted token storage

## MCP Tools

### 1. FreeBusy Tool

Queries Google Calendar to check availability and scheduled events for a given time range.

**Use Case**: "Am I free tomorrow afternoon?"

### 2. Create Event Tool

Creates calendar events in Google Calendar with specified details such as:
- Event title/description
- Start and end times
- Attendees
- Location

**Use Case**: "Create a meeting tomorrow at 2pm with Alice"

## Project Structure

```
calendar-tool/
├── docs/                        # Documentation
│   ├── CERTIFICATES.md          # Certificate setup guide
│   ├── CICD.md                  # CI/CD pipeline
│   └── INSTALL.md               # Installation instructions
├── src/
|   ├── calendar_agent/          # Main calendar agent service
|   ├── calendar_agent_api/      # API gateway layer
|   ├── calendar_install/        # AWS deployment automation
|   ├── calendar_mcp/            # MCP service with Google Calendar tools
|   └── calendar_oauth_redirect/ # Google OAuth redirect handler
└── README.md                    # Project overview (this document)
```

## Getting Started

### Prerequisites

- Python 3.13+
- Redis server (tested with Redis Cloud)
- AWS account (for cloud deployment)
- Google Cloud project with OAuth 2.0 credentials
- OpenAI API account

### Installation

For detailed installation instructions, see:
- **[Installation Guide](docs/INSTALL.md)** - Step-by-step setup instructions
- **[Certificate Guide](docs/CERTIFICATES.md)** - Certificate generation and configuration

### AWS Deployment

The project includes automation scripts in `src/calendar_install/` for:

- Creating Lambda functions and layers
- Setting up API Gateway with custom domains
- Configuring mTLS truststores
- Managing IAM roles and policies
- Deploying certificates and configuration settings to Parameter Store

### Local Development

1. Generate certificates using the certificate manager
2. Configure environment variables
3. Run FastAPI servers for each component

See the installation guides for detailed steps.

## Configuration

Configuration is managed through AWS Parameter Store (production) or environment variables (local). Key configuration includes:

- Google OAuth credentials and scopes
- Redis connection details
- HMAC secrets for request signing
- Certificate paths and passwords
- Slack bot configuration (if using Slack integration)

## Authentication Flow

1. User links Google account via OAuth redirect server
2. OAuth tokens are encrypted and stored in Redis
3. Agent requests include HMAC signatures, Slack requests include Slack signature
4. MCP API Gateway requires mTLS before invoking MCP
4. MCP service verifies signatures and uses stored, encrypted Google tokens
5. Google tokens are automatically refreshed when expired

## Contributing

When contributing to this project:

1. Follow the existing code style
2. Following the existing file structures
3. Recommended Ruff and MyPy for linting and formatting
4. Test both local and AWS deployment scenarios, if applicable
5. Test both client and Slack entrypoint scenarios, if applicable

### Development Workflow

1. **Create a branch** from the main branch:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix-name
   ```

2. **Make your changes** and ensure they follow the project guidelines

3. **Commit your changes** with clear, descriptive commit messages:
   ```bash
   git commit -m "Add feature: brief description"
   ```

4. **Push your branch** to the remote repository:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** on GitHub:
   - Provide a clear title and description
   - Reference any related issues
   - Ensure all tests pass and linting checks succeed
   - Request review from maintainers

6. **Respond to feedback** and make any requested changes

Once your pull request is approved, it will be merged into the main branch.

## Security Considerations

- Never commit secrets or certificates to version control
- Use Parameter Store (SeecureStrings with KMS encryption) for all sensitive configuration
- Regularly rotate HMAC secrets and OAuth credentials
- Monitor CloudWatch logs for authentication failures
- Keep certificates up to date and rotate periodically

## Author

**Tommy Armstrong**

## License

**License TBD** - All rights reserved.

Copyright © 2025 Tommy Armstrong. All rights reserved.

(Note: License terms to be determined.)

## Support

For issues and questions, please refer to:
- Installation documentation: `docs/INSTALL.md`
- Certificate setup: `docs/CERTIFICATES.md`

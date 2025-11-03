# 🔁 CONTEXT SUMMARY FOR CONTINUATION

I’m building an Agent → MCP authentication system in AWS. Here’s the architecture and current progress:

## 🏗️ System Overview

- Architecture:

    - MCP: Deployed behind AWS API Gateway. Integrated with Google Calendar using OAuth. Provides calendar freebusy and createevent tools.

    - Agent: Runs as an AWS Lambda function that calls the MCP securely and communicates with clients using LLM for NLP.

    - Agent API: Deployed behind AWS API Gateway. Entry point for client and Slack; handles authentication and authorization and invokes Agent.

    - OAuth API: Deployed behind AWS API Gateway. Handles redirects to Google OAuth and caches user tokens and scopes (encypted)

    - Redis Cloud cache for Google OAuth tokens (encrypted), Agent → MCP HMAC nonces, MCP manifest and schemas

    - Test Client: Exchanges messages with Agent API to invoke the system

    - Slack bot integration: Exchanges messages with Agent API to invoke the system

    - OpenAI GPT: NLP, schema parsing, tool selection and request creation

    - AWS components:
        - IAM
        - CloudWatch
        - Parameter Store (and SecretStrings)
        - S3 for mTLS truststore
        - Lambda
        - API Gateway HTTP API v2
        - Certficate Manager for mTLS

    - Local alternative to deploy behind FastAPI for dev test with sectrets in env variables and self signed certs for mTLS

- Security
    - Client → Agent API: Bearer token
    - Slack → Agent API: Slack signature
    - Agent → MCP: mTLS + HMAC (timestamp, nonce, shared secret)
    - MCP Gateway domain = calendar-mcp.tommyarmstrong.uk, custom domain with truststore in S3
    - Secrets stored as Parameter Store SharedSecrets with KMS
    - Minimum rights IAM policies

- CI/CD
    - Pyright and Ruff IDE extentions
    - Git precommint hooks run MyPy and Ruff
    - GitHub deploys all merges to main into AWS Lambdas
    - Custom scripts build and integrate all AWS components and generate certs, with extensive documentation


## 🔐 Future Work:

- Testing strategy and tests
- Multiuser support
- Incorporate additional models (DeepSeek, Gemini, Claude)
- Autmated certificate rotation
- Improved logging and error handling
- Validation of LLM responses against MCP schemas
- Additonal tools
- Additional endpoints
- Chaining tools
- Production AWS system deployed from release tags on main
-

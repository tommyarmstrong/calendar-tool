# Calendar Tool Installation Guide

This guide covers the installation and deployment of the Calendar Tool system, which consists of three main components:

- **Calendar Agent** - Core Lambda function for calendar operations
- **Calendar Agent API** - API Gateway for external access
- **Calendar MCP** - Model Context Protocol (MCP) server for calendar integration
- **Google OAuth Redirect** - Supports linking the MCP with Google accounts for authorization using OAuth

The **Calendar Install** directory contains tools to deploy the system, into Amazon Web Services (AWS).


## 1. 🔄 Clone Repository

```bash
# Clone the calendar-tool repository
git clone https://github.com/tommyarmstrong/calendar-tool.git
cd calendar-tool
```

### Repository Structure

The repository contains the following main components:

```
calendar-tool/
├── src/
│   ├── calendar_agent/             # Core calendar processing Lambda
│   │   ├── app/                    # Application modules
│   │   │   ├── main.py             # Main application logic
│   │   │   └── ...
│   │   ├── infrastructure/         # Infrastructure modules
│   │   ├── services/               # Service modules
│   │   ├── agent_config.json       # Agent configuration
│   │   └── agent_handler.py        # Lambda handler
│   ├── calendar_agent_api/         # API Gateway for external access
│   │   ├── app/                    # Application modules
│   │   │   ├── main.py             # Main application logic
│   │   │   └── ...
│   │   ├── auth/                   # Authentication modules
│   │   ├── clients/                # Client modules
│   │   ├── infrastructure/         # Infrastructure modules
│   │   ├── services/               # Service modules
│   │   ├── agent_api_config.json   # API configuration
│   │   ├── agent_api_handler.py    # Lambda handler
│   │   └── fast_api_server.py      # FastAPI server for local dev
│   ├── calendar_mcp/               # Model Context Protocol server
│   │   ├── app/                    # Application modules
│   │   │   ├── main.py             # Main application logic
│   │   │   └── ...
│   │   ├── auth/                       # Authentication modules
│   │   ├── fast_api_server/            # FastAPI server for local dev
│   │   │   ├── server.py               # FastAPI server
│   │   │   └── google_oauth_server.py  # OAuth server
│   │   ├── infrastructure/             # Infrastructure modules
│   │   ├── mcp/                        # MCP protocol modules
│   │   ├── services/                   # Service modules
│   │   ├── tools/                      # MCP tools
│   │   ├── mcp_config.json             # MCP configuration
│   │   └── mcp_handler.py              # Lambda handler
│   ├── calendar_oauth_redirect/    # Google OAuth redirect handler
│   │   ├── app/                    # Application modules
│   │   │   ├── main.py             # Main application logic
│   │   │   └── ...
│   │   ├── auth/                   # Authentication modules
│   │   ├── infrastructure/         # Infrastructure modules
│   │   ├── services/               # Service modules
│   │   ├── redirect_config.json    # OAuth redirect configuration
│   │   ├── redirect_handler.py     # Lambda handler
│   │   └── fast_api_server.py      # FastAPI server for local dev
│   └── calendar_install/           # Deployment tools
│       ├── certificates/           # SSL certificates directory
│       ├── aws_api_gateway_manager.py
│       ├── aws_iam_manager.py
│       ├── aws_lambda_manager.py
│       ├── aws_parameter_manager.py
│       ├── CERTIFICATES_README.md      # Certificates documentation
│       └── INSTALL_README.md           # This file
```


## 2. 📅 Google Cloud Configuration

Take the following steps to enable the Calendar MCP to authenticate to the Google API using OAuth and then take actions on the Google Calendar:

- **Launch Google Cloud Console** by browsing to https://console.cloud.google.com.

- **Enable the API** by selecting APIs & Services → Enable APIs an Services → Google Calendar API → Enable.

- **OAuth consent** is created by:
    - Selecting APIs & Services → OAuth consent screen → Clients
    - Selecting Create client → Application type to "Web application" and giving a name like "mcp-calendar-web"
    - Adding an "Authorized redirect URI" of "http://localhost:8001/oauth/callback"

- **Client ID and Client Secret** will be created. You need to store these for later use.

- **Scopes** can be created by selecting Data Access → Add or remove scopes. Add the scopes:
    - ./auth/calendar.calendars.readonly
    - ./auth/calendar.calendars.events

- **Environment variables** should be created for Cliend ID and Client Secret:
```bash
# Google OAuth secrets
GOOGLE_CLIENT_SECRET = ***************
GOOGLE_CLIENT_ID = ***************
```
The Google client ID is a "pseudo-secret" really. We store it encrypted.

- **Optional environment variables** can be set for the redirect URI and the scopes, although these will be read from the default JSON config for the MCP and are also defaulted.
```bash
# Google OAuth parameters
GOOGLE_REDIRECT_URI = http://localhost:8001/oauth/callback
GOOGLE_SCOPES=https://www.googleapis.com/auth/calendar.events,https://www.googleapis.com/auth/calendar.readonly
```

## 3. ⚙️ General Parameters and Secrets

Configure the following environment variables on your local system.

```bash
# Infrastructure parameters and secrets
export OPENAI_API_KEY="your-openai-key"
export REDIS_HOST="your-redis-host"
export REDIS_PASSWORD="your-redis-password"
export REDIS_PORT="your-redis-port"

# Aplication configuration
export CALENDAR_MCP_URL="https://localhost:8000"   # For local testing
export CALENDAR_MCP_DEFAULT_TZ="Europe/London"     # Set as required
```

## 4. 🔐 Secrets and Certificates

To generate calendar MCP certificates and secrets run the following:

```bash
# Generate and distribute test certificates
cd src/calendar_install
python generate_certs.py
```

This will create the directory `src/calendar_install/certificates`. Keep this directory secure and exclude from git.

Two shell scripts will be created `src/calendar_install/certificates/set_env.sh` and `src/calendar_install/certificates/append_to_zshrc.sh`.

CHECK these scripts for any potential clashes with existing environment variables before running them.

To permanently set environment variables execute (recommended):

```bash
./src/calendar_install/certificates/append_to_zshrc.sh && source ~/.zshrc
```

To export environment variables into the shell execute:

```bash
source src/calendar_intall/certificates/set_env.sh
```

🔒 **Security Notice**

Permenantly delete the files `src/calendar_intall/certificates/set_env.sh` and `src/calendar_intall/certificates/append_to_zshrc.sh` so that passwords are not left on file.


## 5. 💻 Local Deployment

### Pre-requisites

It is helpful to deploy locally as well as in AWS. This will help with trouble shooting. To run system locally, take the following steps (where Ngrok is optional but recommended).

1. **Code** has been deployed by cloning the Github repository.
2. **Pre-requisite packages** should be installed (ideally in venv or conda environments):
- Calendar Agent packages:
    - openai
    - redis
    - requests
    - requests_pkcs12
- Calendar Agent API packages:
    - fastapi
    - redis
    - slack-sdk
- Calendar MCP
    - cryptography
    - fastapi
    - google-auth
    - google-auth-oauthlib
    - google-api-python-client
    - pydantic
    - redis
    - ngrok (optional)
3. **Pre-requisite API accounts** for Google Calendar, OpenAI, Redis and Ngrok (optional) should be available.
4. **Pre-requisite configuration** including environment variables (section x), Google configuration (section x) and certificates (section x) should be complete.

### Start the Servers

Ensure the environment variable for the MCP server address is set to localhost on port 8000: ```CALENDAR_MCP_URL=https://localhost:8000```. From different termainals, start-up the servers.

**MCP Server**
Start the server on port 8000:

```bash
# Start the MCP server in FastAPI
cd src/calendar_agent_mcp
uvicorn fast_api_server.server:app --reload --port 8000
```

If certificates has been configured then the MCP server can be started with mTLS. This will more closely replicate the AWS deployment.

```bash
# Start the MCP server in FastAPI with mTLS certificates
uvicorn fast_api_server.server:app --reload --port 8000 \
--ssl-certfile certificates/server.crt \
--ssl-keyfile certificates/server.key \
--ssl-ca-certs ccertificates/a.crt \
--ssl-cert-reqs 2
```

**Google OAuth Redirect Server**
Start the Google OAuth Redirect server. This is part of the MCP module and runs on http in local environment.

```bash
# Start the Google OAuth server in FastAPI
uvicorn fast_api_server.server:app --reload --port 8001
```

**Agent API Server**
Start the Agent API server on port 9000:

```bash
# Start the Agent API server in FastAPI
cd src/calendar_agent_api
uvicorn fast_api_server:app --reload --port 9000

```

**Ngrok Server**:
Start the Ngrok server port-forwarding to port 9000:

```bash
# Start the Ngrok server
ngrok http 9000
```

The Ngrok terminal should show the externally available URL which clients can connect to. It will be of the form: ```https://d95d104e1fce.ngrok-free.app``` and point to ```http://localhost:9000``` (the local calendar_agent_api address).

Skip to section XX to see how to run the test client.


## 6. ☁️ AWS Deployment

### Pre-requisites

To deploy into AWS you will need:

1. **Code** is available after cloning the Github repository.
2. **AWS CLI** configured with appropriate permissions
3. **AWS services** available:
- API Gateway
- CloudWatch
- IAM
- Lambda
- Parameter Store (part of Systems Manager Service)
- S3
- Systems Manager
4. **Pre-requisite API accounts** for Google Calendar, OpenAI and Redis should be available.
5. **Pre-requisite configuration** including environment variables (section x), Google configuration (section x) and certificates (section x) should be complete.
6. **Public DNS Server** to set a CNAME for the AWS Certificate Manager

The AWS service requirements will likely be within the free tier or at a very low cost, please check current pricing.

### AWS Deployment Scripts

There are scripts in ```src/calendar_install/``` directory for configuring AWS services. These scripts need to be run for each of the three modules. They import configuration for the module from a configuration JSON file.

To configure or reconfigure AWS services individually the following scripts are available:
- **aws_api_gateway_manager.py** configures API routes for the module (if required)
- **aws_iam_manager.py** configures IAM roles and policies routes for the module
- **aws_lambda_manager.py** configures the Lambda function for the module
- **aws_parameter_manager.py** paramters and secrets for the module

In addition there is a script called ```aws_deploy.py``` which will import the individual scripts and execute them in the right order.

The install order is:
1. Calendar MCP
2. Calendar Agent
3. Calendar Agent API
4. Calendar OAuth Redirect

Each module has its own configuration file:

- `src/calendar_mcp/mcp_config.json` - Calendar MCP configuration
- `src/calendar_agent/agent_config.json` - Calendar Agent configuration
- `src/calendar_agent_api/agent_api_config.json` - Calendar Agent API configuration
- `src/calendar_oauth_redirect/redirect_config.json` - Calendar OAuth Redirect configuration

#### Deploy Lambda Functions

Run the scripts in the following order for each Lambda function, checking for errors:

```bash
# Deploy parameters and secrets
python aws_parameter_manager.py --config-file <config-file-path>

# Deploy IAM roles and policies
python aws_iam_manager.py --config-file <config-file-path>

# Deploy Lambda function
python aws_lambda_manager.py --config-file <config-file-path>

# Deploy API Gateway routes
python aws_api_gateway_manager.py --config-file <config-file-path>
```

Or run the deploy script to deploy all services in sequence:

```bash
# Deploy all of the services in sequence
python aws_deploy.py --config-file <config-file-path>
```

**Note:** Repeat the above deployment process for each of the four Lambda functions using their respective configuration files:

1. **Calendar MCP**: `../calendar_mcp/mcp_config.json`
2. **Calendar Agent**: `../calendar_agent/agent_config.json`
3. **Calendar Agent API**: `../calendar_agent_api/agent_api_config.json`
4. **Calendar OAuth Redirect**: `../calendar_oauth_redirect/redirect_config.json`

#### 🚧 Update Paramaters

**NEED TO COMPlETE**

Modify `calendar_mcp_url` and `gogole_redirect_uri`with the invoke URL for the MCP API Gateway.

#### Test the AWS deployment

At this stage the environment should work and you can test it using the Calendar client (section 7).

#### mTLS in AWS

To ensure the Calendar Agent can only talk to the MCP with mTLS run the script `aws_mTLS_manager.py`.

```bash
cd calendar_install
python aws_mTLS_manager.py --bucket <globally-unique-bucket-name> --domain <calendar-mcp.example.com>
```

Now create a CNAME in your DNS to point to the MCP domain mapping.


## 7. 💻 Connect with Calendar MCP Client

### 7.1 Local Server (FastAPI)

Make sure you have a valid client bearer token. For testing this is in your environment variable CALENDAR_BEARER_TOKEN.

```bash
# Find the test bearer token
printenv | grep CALENDAR_BEARER_TOKEN
```

Change into the Agent API directory `src/calendar_agent_api` then execute the client in `clients/calendar_client.py`.

1. Ask a question that the LLM should associate with the MCPs "availability" tool.

```bash
# Run the Agent Client
cd src/calendar_agent_api
python clients/calendar_client.py --ngrok --token <bearer-token-value> "Am I free tomorrow?"
```

2. Make a request that the LLM should associate with the MCPs "create event" tool.

```bash
# Run the Agent Client
cd src/calendar_agent_api
python clients/calendar_client.py --ngrok --token <bearer-token-value> "Create an meeting on Wednesday morning to discuss the product release plan. Invite steve@example.com. Location is the Farringdon office but add a google meet link."
```

### 7.2 AWS Service

As above, but don't use the `--ngrok` flag and instead add in the `--url agent-api-aws-invoke-url`.

## 8. 💬 Configure Slack

### Create a Slack app & bot user

1. Go to https://api.slack.com/apps → Create New App.

2. Enter basic information

3. OAuth & Permissions → Scopes → Add Bot Token Scopes:
- app_mentions:read
- chat:write

4. Install to Workspace → authorize.
- Copy Bot User OAuth Token (starts with xoxb-…).

5. Event Subscriptions → Enable Events: On
- Add request URL.
- This is the Agent URL.
- For local testing this is the Ngrok URL + the /agents/calendar route
- Slack will send a challenge to the API, which must return it.

6. Test with an @ mention in a channel with the bot
 - For example: @calendar When am I free on Friday afternoon?



## 🔍 Troubleshooting


### Common Issues


### Logs

Check CloudWatch logs for each component:
- `/aws/lambda/calendar_agent`
- `/aws/lambda/calendar_agent_api`
- `/aws/lambda/calendar_mcp`
- `/aws/lambda/calendar_oauth_redirect`

## ➡ Next Steps

After successful installation:

## 💡 Support

For issues or questions:

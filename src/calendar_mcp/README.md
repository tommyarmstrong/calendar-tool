# Calendar MCP Service

A Model Context Protocol (MCP) server that provides Google Calendar integration with OAuth authentication. This service exposes calendar tools through a standardized MCP interface, allowing AI assistants and other applications to interact with Google Calendar.

## Features

- **Google Calendar Integration**: Create events and check free/busy status
- **OAuth Authentication**: Secure Google OAuth 2.0 flow with token management
- **MCP Protocol**: Standardized Model Context Protocol interface
- **Redis Caching**: Token storage and idempotency protection
- **Multiple Deployment Options**: FastAPI server or AWS Lambda
- **Event Color Support**: Create events with custom colors
- **Conference Support**: Generate Google Meet links for events

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MCP Client   │───▶│  Calendar MCP   │───▶│ Google Calendar │
│  (AI Assistant)│    │     Service     │    │      API        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Redis Cache   │
                       │  (Token Store)  │
                       └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.12+
- Redis server
- Google Cloud Console project with Calendar API enabled

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/tommyarmstrong/calendar-mcp.git
   cd calendar-mcp
   ```

2. **Install dependencies**
   ```bash
   pip install -e .
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Server Configuration
CALENDAR_MCP_PORT=8000
CALENDAR_MCP_BASE_URL=http://localhost:8000
CALENDAR_MCP_DEFAULT_TZ=Europe/London

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:8000/oauth/callback
GOOGLE_SCOPES=https://www.googleapis.com/auth/calendar

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# MCP Authentication
MCP_BEARER_TOKEN=your_secure_token
```

### Google OAuth Setup

1. **Create a Google Cloud Project**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one

2. **Enable Calendar API**
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google Calendar API" and enable it

3. **Create OAuth Credentials**
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Set application type to "Web application"
   - Add authorized redirect URI: `http://localhost:8000/oauth/callback`
   - Copy the Client ID and Client Secret to your `.env` file

### Running the Service

#### Option 1: FastAPI Development Server

```bash
# Start Redis (if not running)
redis-server

# Run the FastAPI server
uvicorn src.fast_api_server.server:app --reload --port 8000
```

#### Option 2: AWS Lambda

The service is designed to work with AWS Lambda. Deploy using your preferred method (Serverless Framework, AWS SAM, etc.).

### Authentication Flow

1. **Start OAuth Flow**
   ```bash
   curl http://localhost:8000/oauth/start
   ```

2. **Complete OAuth in Browser**
   - The redirect will take you to Google's OAuth consent screen
   - Grant permissions for calendar access
   - You'll be redirected back with a success message

## API Reference

### MCP Endpoints

#### Get Manifest
```http
GET /.well-known/mcp/manifest
```

Returns the MCP server manifest with available tools and endpoints.

#### List Tools
```http
GET /mcp/tools
Authorization: Bearer <token>
```

Returns available calendar tools.

#### Call Tool
```http
POST /mcp/tools/call
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "calendar.create_event",
  "arguments": {
    "title": "Meeting with Team",
    "start": "2024-01-15T10:00:00+01:00",
    "end": "2024-01-15T11:00:00+01:00",
    "attendees": ["colleague@example.com"],
    "description": "Weekly team sync",
    "location": "Conference Room A",
    "conference": true,
    "color_id": "2"
  }
}
```

### Available Tools

#### `calendar.create_event`

Creates a new calendar event.

**Parameters:**
- `title` (string, required): Event title
- `start` (string, required): Start time (ISO 8601 format)
- `end` (string, required): End time (ISO 8601 format)
- `attendees` (array, required): List of attendee email addresses
- `description` (string, optional): Event description
- `location` (string, optional): Event location
- `conference` (boolean, optional): Generate Google Meet link
- `color_id` (string, optional): Event color (1-11)

**Color IDs:**
- `1`: Lavender
- `2`: Sage
- `3`: Grape
- `4`: Flamingo
- `5`: Banana
- `6`: Tangerine
- `7`: Peacock
- `8`: Graphite
- `9`: Blueberry
- `10`: Basil
- `11`: Tomato

#### `calendar.freebusy`

Checks free/busy status for specified time windows.

**Parameters:**
- `window_start` (string, required): Start of time window (ISO 8601)
- `window_end` (string, required): End of time window (ISO 8601)
- `calendars` (array, optional): List of calendar IDs to check

## Usage Examples

### Python Client

```python
import requests

BASE_URL = "http://localhost:8000"
TOKEN = "your_bearer_token"

# Create an event
response = requests.post(
    f"{BASE_URL}/mcp/tools/call",
    headers={"Authorization": f"Bearer {TOKEN}"},
    json={
        "name": "calendar.create_event",
        "arguments": {
            "title": "Team Meeting",
            "start": "2024-01-15T10:00:00+01:00",
            "end": "2024-01-15T11:00:00+01:00",
            "attendees": ["team@company.com"],
            "description": "Weekly sync",
            "conference": True,
            "color_id": "2"
        }
    }
)

print(response.json())
```

### cURL Examples

```bash
# List available tools
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/mcp/tools"

# Check free/busy status
curl -X POST "http://localhost:8000/mcp/tools/call" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "calendar.freebusy",
    "arguments": {
      "window_start": "2024-01-15T08:00:00+01:00",
      "window_end": "2024-01-15T18:00:00+01:00"
    }
  }'
```

## Development

### Project Structure

```
src/
├── app/                 # Application configuration and main entry point
├── auth/               # Google OAuth authentication
├── clients/            # Example client implementations
├── fast_api_server/    # FastAPI development server
├── mcp/                # MCP protocol implementation
├── processor/          # AWS Lambda processor
├── services/           # Platform services (Redis, AWS)
└── tools/              # Calendar tool implementations
```

### Code Quality

The project uses:
- **Ruff** for linting and formatting
- **MyPy** for type checking
- **4-space indentation** (as per `.cursorrules`)

Run quality checks:
```bash
# Linting
ruff check src/

# Type checking
mypy src/

# Formatting
ruff format src/
```

### Testing

```bash
# Run the demo client
python src/clients/demo_client.py

# Test with cURL
bash src/clients/demo_curl.sh
```

## Deployment

### AWS Lambda

The service is designed for serverless deployment on AWS Lambda with API Gateway. The `handler.py` provides the Lambda entry point.


## Security

- **Bearer Token Authentication**: All MCP endpoints require valid bearer tokens
- **OAuth 2.0**: Secure Google authentication with token refresh
- **Redis Security**: Password-protected Redis connections
- **Idempotency**: Prevents duplicate event creation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run quality checks
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the logs in `logs/calendar-mcp` for debugging
- Ensure all environment variables are properly configured

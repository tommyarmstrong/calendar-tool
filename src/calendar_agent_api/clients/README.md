# Calendar Agent Client

A Python command-line client for interacting with the Calendar Agent API.

## Usage

```bash
python src/clients/calendar_client.py "Your message here" "your_bearer_token_here"
```

## Examples

### Basic usage
```bash
python src/clients/calendar_client.py "What meetings do I have today?" ya29.a0AfH6SMC...
```

### With custom server
```bash
python src/clients/calendar_client.py "Create a meeting tomorrow at 2pm" ya29.a0AfH6SMC... --url http://localhost --port 8080
```

### Pretty print response
```bash
python src/clients/calendar_client.py "Show my calendar" ya29.a0AfH6SMC... --pretty
```

### Verbose output
```bash
python src/clients/calendar_client.py "What's my schedule?" ya29.a0AfH6SMC... --verbose
```

## Command Line Options

- `message`: The message to send to the calendar agent (required)
- `bearer_token`: The OAuth bearer token for authentication (required)
- `--url`: Base URL of the agent server (default: http://127.0.0.1)
- `--port`: Port of the agent server (default: 9000)
- `--endpoint`: API endpoint path (default: /agents/calendar)
- `--pretty`: Pretty print the JSON response
- `--verbose`: Show verbose output including request details

## Installation

Make sure you have the required dependencies:

```bash
pip install requests
```

Or install the full project:

```bash
pip install -e .
```

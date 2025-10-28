# Calendar Tool Certificates

This document describes all the certificates created by the `CertificateManager` in the calendar tool infrastructure.

## Certificate Overview

The calendar tool uses a certificate-based security model with mutual TLS (mTLS) authentication. All certificates are created using the `CertificateManager` class and follow a hierarchical structure with a root CA certificate signing all other certificates.

## Certificate Types and Details

### 1. **CA Certificate (Root Certificate)**
- **Type**: Root CA certificate (X.509)
- **Purpose**: Root of trust for the entire certificate chain; signs all other certificates
- **Files Created**:
  - `ca.crt` (PEM format)
  - `ca.key` (private key)
  - `ca.crt.b64` (base64 encoded for environment variables)
- **Distribution**:
  - **File Copy**: Stored in `certificates/` directory
  - **Environment Variable**: `CALENDAR_MCP_CA_CERT_B64` (base64 encoded)
- **Validity**: 365 days (1 year)
- **Key Size**: 2048 bits RSA
- **Usage**: Used to sign all other certificates in the system

### 2. **Client Certificate (Agent)**
- **Type**: Client certificate (X.509)
- **Purpose**: Authenticates the calendar agent for mTLS communication
- **Files Created**:
  - `client.crt` (PEM format)
  - `client.key` (private key)
- **Distribution**:
  - **File Copy**: Stored in `certificates/` directory
  - **P12 Bundle**: `client.p12` and `client.p12.b64` (base64 encoded)
  - **Environment Variable**: `CALENDAR_MCP_CLIENT_P12` (base64 encoded P12 bundle)
- **Validity**: 60 days
- **Key Size**: 2048 bits RSA
- **Usage**: Client authentication for mTLS

### 3. **Server Certificate (MCP Service)**
- **Type**: Server certificate (X.509)
- **Purpose**: Secures the MCP (Model Context Protocol) service endpoint
- **Files Created**:
  - `server.crt` (PEM format)
  - `server.key` (private key)
- **Distribution**:
  - **File Copy**: Stored in `certificates/` directory
  - **MCP Copy**: Copied to `calendar_mcp/certificates/` directory for local development
- **Validity**: 60 days
- **Key Size**: 2048 bits RSA
- **Usage**: Secures the MCP service endpoint with Subject Alternative Name (SAN) support

## Additional Files Created

### 4. **Truststore Bundle**
- **Type**: Certificate bundle (PEM format)
- **Purpose**: Contains the CA certificate for trust verification
- **Files Created**:
  - `truststore.pem` (PEM format)
- **Distribution**:
  - **File Copy**: Stored in `certificates/` directory
- **Usage**: Used by applications to verify certificate chains

### 5. **P12 Bundle (Client Authentication)**
- **Type**: PKCS#12 certificate bundle
- **Purpose**: Contains client certificate and private key for mTLS authentication
- **Files Created**:
  - `client.p12` (PKCS#12 format)
  - `client.p12.b64` (base64 encoded)
- **Distribution**:
  - **File Copy**: Stored in `certificates/` directory
  - **Environment Variable**: `CALENDAR_MCP_CLIENT_P12` (base64 encoded)
- **Password**: Stored in `CALENDAR_MCP_CLIENT_P12_PASSWORD` environment variable
- **Usage**: Client authentication for mTLS connections

## Certificate Chain Structure

```
Root CA Certificate (ca.crt)
├── Client Certificate (client.crt)
└── Server Certificate (server.crt)
```

## Security Features

- **Mutual TLS (mTLS)**: Both client and server authenticate each other
- **Subject Alternative Name (SAN)**: Server certificate supports multiple hostnames
- **Strong Encryption**: RSA 2048-bit for all certificates
- **Short Validity**: 60-day validity for end certificates, 1-year for CA
- **Base64 Encoding**: Certificates encoded for environment variable storage

## Environment Variables

The following environment variables are created by the certificate manager:

- `CALENDAR_MCP_CA_CERT_B64`: Base64 encoded CA certificate
- `CALENDAR_MCP_CLIENT_P12`: Base64 encoded P12 bundle
- `CALENDAR_MCP_CLIENT_P12_PASSWORD`: Password for P12 bundle
- `CALENDAR_BEARER_TOKEN`: Random bearer token for authentication
- `CALENDAR_TOKEN_ENCRYPTION_KEY`: Fernet key for token encryption
- `CALENDAR_MCP_URL`: MCP service URL (https://localhost:8000)
- `CALENDAR_MCP_DEFAULT_TZ`: Default timezone (Europe/London)

## Certificate Management

Certificates are managed through the `CertificateManager` class which provides:

- **Creation**: Generate new certificates with proper signing
- **Environment Scripts**: Create `set_env.sh` and `append_to_zshrc.sh` scripts
- **MCP Integration**: Copy server certificates to calendar_mcp directory
- **Cleanup**: Remove intermediate files (CSR, extension files, serial files)
- **Base64 Encoding**: Encode certificates for environment variable storage

## File Locations

All certificates are stored in the `certificates/` directory with the following structure:

```
certificates/
├── ca.crt                    # CA certificate (PEM)
├── ca.key                    # CA private key
├── ca.crt.b64               # Base64 encoded CA certificate
├── client.crt               # Client certificate (PEM)
├── client.key               # Client private key
├── client.p12               # P12 bundle for client auth
├── client.p12.b64           # Base64 encoded P12 bundle
├── server.crt               # Server certificate (PEM)
├── server.key               # Server private key
├── truststore.pem           # Truststore bundle
├── set_env.sh               # Environment setup script
└── append_to_zshrc.sh       # Zshrc append script
```

## Usage in Application

The certificates are used throughout the calendar tool infrastructure:

1. **MCP Service**: Uses `server.crt` and `server.key` for HTTPS termination
2. **Calendar Agent**: Uses `client.p12` for mTLS authentication
3. **Trust Verification**: Uses `ca.crt` and `truststore.pem` for certificate validation
4. **Environment Setup**: Uses generated scripts to set up development environment

## Generated Scripts

The certificate manager creates two helper scripts:

### `set_env.sh`
- Sets environment variables for the current session
- Contains base64 encoded certificates and generated secrets
- Can be sourced: `source certificates/set_env.sh`

### `append_to_zshrc.sh`
- Appends environment variables to `~/.zshrc`
- Creates backup of existing `.zshrc` before modification
- Removes existing calendar MCP variables before adding new ones
- Run with: `./certificates/append_to_zshrc.sh && source ~/.zshrc`

## Security Considerations

- **Private Keys**: Never stored in version control
- **Short Validity**: 60-day certificates require regular renewal
- **Random Secrets**: Bearer tokens and encryption keys are randomly generated
- **Base64 Encoding**: Certificates encoded for safe environment variable storage
- **Cleanup**: Intermediate files are removed after generation

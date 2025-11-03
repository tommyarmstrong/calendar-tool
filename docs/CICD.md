# CI/CD for calendar-tool

This repo uses GitHub Actions → AWS Lambda via OIDC (no long-lived AWS keys) to deploy only the Lambda functions whose code changed.

## How it works (high level)

**Trigger**: On push to main when files change under:

- `src/calendar_agent/**`
- `src/calendar_agent_api/**`
- `src/calendar_mcp/**`
- `src/calendar_oauth_redirect/**`
 - `src/calendar_shared/**`

**Detect changes**: A detect job runs `git diff` between the push range and sets booleans for each folder (ignoring Markdown, config, and other noise). If anything under `src/calendar_shared/**` changed, the job forces all four deploy flags to `true` so every Lambda is rebuilt against the new shared code.

**Deploy**: There are four independent jobs (`deploy_*`). Each job runs only if its corresponding folder changed (or if shared code changed). Packaging uses a folder-local `.lambdaignore` (code-only; all deps come from Layers) and injects shared files into each function’s package.

## Files to know

- **Workflow**: `.github/workflows/deploy-on-main.yml`
- **Per-function code folders**:
  - `src/calendar_agent/`
  - `src/calendar_agent_api/`
  - `src/calendar_mcp/`
  - `src/calendar_oauth_redirect/`
 - **Shared code**:
   - `src/calendar_shared/` (platform manager, redis manager, crypto, HMAC, etc.)
- **Optional per-folder ignore file**: `src/<function>/.lambdaignore`
  - (e.g. ignore README.md, configs, certs, etc.)

## Shared code handling

- At package time, the workflow injects real files from `src/calendar_shared/` into each function’s `shared_infrastructure/` directory inside the zip. This resolves symlinks to actual file content in the Lambda artifact.
- Mapping highlights:
  - `shared_infrastructure/platform_manager.py` ← `src/calendar_shared/aws_platform_manager.py` (AWS-specific variant)
  - `shared_infrastructure/redis_manager.py` ← `src/calendar_shared/redis_manager.py`
  - `shared_infrastructure/hmac_auth.py` ← `src/calendar_shared/hmac_auth.py`
  - `shared_infrastructure/cryptography_manager.py` ← `src/calendar_shared/cryptography_manager.py`
- In the repo, only `__init__.py` is tracked under each `shared_infrastructure/`; the other entries are symlinks and are intentionally untracked. The workflow step replaces them with the real shared files in the zip.

## AWS OIDC role

We assume a dedicated IAM role from GitHub via OpenID Connect:

- **OIDC Provider URL**: `https://token.actions.githubusercontent.com`
- **Audience**: `sts.amazonaws.com`
- **Role ARN** (saved as a GitHub secret): `AWS_ROLE_TO_ASSUME`

**Example value**:
```
arn:aws:iam::<ACCOUNT_ID>:role/calendar-tool-gh-actions-deploy
```

**Trust policy** (key condition):
```json
"token.actions.githubusercontent.com:sub": "repo:<ORG_OR_USER>/calendar-tool:ref:refs/heads/main"
```

(Optionally restrict to a specific workflow file using `:workflow:.github/workflows/deploy-on-main.yml`.)

**Permissions policy** (least privilege):
- `lambda:UpdateFunctionCode`, `lambda:PublishVersion`
- **Resource ARNs**: the four Lambda functions you deploy (region/account must match).

**In GitHub**: Settings → Secrets and variables → Actions

Create secret `AWS_ROLE_TO_ASSUME` with the full role ARN.

## What gets deployed

- Only code from each function folder is zipped (plus the injected shared files).
- No pip install here—dependencies live in Lambda Layers.
- `.lambdaignore` rules are applied when creating the ZIP (e.g. ignore `*.md`, `*.pem`, `agent_config.json`, etc.).
 - Symlinks under `shared_infrastructure/` are dereferenced by injecting the corresponding files from `src/calendar_shared/` before zipping.

## Add a new Lambda function

1. **Create the folder** under `src/`, e.g. `src/calendar_newfunc/` with your handler at the folder root.

2. **Add a `.lambdaignore`** in that folder (recommended), e.g.:
   ```
   *.md
   *.pem
   *.crt
   __pycache__/
   ```

3. **Update the workflow** `.github/workflows/deploy-on-main.yml` in three places:

   **a. Trigger paths** (so pushes to this folder start the workflow):
   ```yaml
   on:
     push:
       branches: [ main ]
       paths:
         - "src/calendar_newfunc/**"
         # (keep the others)
   ```

   **b. Detect job (`detect`)** — add folder-specific exclude regex (if any) and a flag:
   ```bash
   # Add after the other EXCL_* lines:
   EXCL_NEW='(^|/)src/calendar_newfunc/some_config\.json$'

   # Set boolean (mirrors others):
   changed_in "src/calendar_newfunc" "${EXCL_NEW}" && NEWFUNC=true
   echo "newfunc=${NEWFUNC}" >> "$GITHUB_OUTPUT"
   ```

   **c. New deploy job** (copy one of the existing `deploy_*` jobs, adjust names/paths):
   ```yaml
   deploy_newfunc:
     name: Deploy calendar_newfunc
     needs: detect
     if: needs.detect.outputs.newfunc == 'true'
     runs-on: ubuntu-latest
     env: { AWS_REGION: us-east-1 }
     steps:
       - uses: actions/checkout@v4
       - uses: aws-actions/configure-aws-credentials@v4
         with:
           role-to-assume: ${{ secrets.AWS_ROLE_TO_ASSUME }}
           aws-region: ${{ env.AWS_REGION }}
       - name: Zip code using .lambdaignore
         working-directory: src/calendar_newfunc
         run: |
           set -euo pipefail
           EXCLUDES=()
           if [ -f .lambdaignore ]; then
             while IFS= read -r line || [ -n "$line" ]; do
               line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
               [ -z "$line" ] || [[ "$line" =~ ^# ]] || EXCLUDES+=(-x "$line")
             done < .lambdaignore
           fi
           EXCLUDES+=(-x "*/__pycache__/*" -x "*.pyc" -x ".DS_Store" -x ".git/**")
           OUT_ZIP="${{ github.workspace }}/package-calendar_newfunc.zip"
           rm -f "$OUT_ZIP"; zip -r9 "$OUT_ZIP" . "${EXCLUDES[@]}"
       - name: Update Lambda code
         run: |
           aws lambda update-function-code \
             --function-name "calendar_newfunc" \
             --zip-file "fileb://${{ github.workspace }}/package-calendar_newfunc.zip" \
             --publish --output json >/dev/null
           echo "Updated calendar_newfunc"
   ```

4. **IAM permissions**: add the new function ARN to the IAM role's policy (Resource list).

## Change detection rules (what won't trigger deploys)

The detect job ignores, repo-wide:

- `*.md`, `.gitignore`, `.ruffignore`, `.mypyignore`, `.mypy.toml`, `.ruff.toml`, `.lambdaignore`, `requirements.txt`, `pyproject.toml`

Plus per-folder config files (e.g., `agent_config.json`) and server scaffolding (`fast_api_server.py`) as encoded in the detect script.

Note: Any change under `src/calendar_shared/**` intentionally triggers all deploy jobs.

If a file you change shouldn't trigger a deploy, add it to the excludes in the detect job and consider putting it in the folder's `.lambdaignore`.

## Quick test flow

1. Edit a single code file in one Lambda folder, push to main.
2. Only that Lambda's deploy job should run.
3. Edit a `README.md` or `requirements.txt`.
4. No deploy should run.

**Check AWS updated time**:
```bash
aws lambda get-function-configuration \
  --function-name calendar_agent \
  --query '{LastModified:LastModified,Version:Version}'
```

## Region & naming

- **Region**: `us-east-1` (set in the workflow `env.AWS_REGION`).
- **Function names**: must match your AWS Lambda function names exactly in the `--function-name` flags and IAM policy ARNs.

If you need to promote this pattern to test vs prod, duplicate the workflow with different trigger rules and point to different IAM roles (one per account/environment) using separate repo/environment secrets.

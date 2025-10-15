#!/usr/bin/env python3
"""
Deploy & update an AWS Lambda function, its IAM role/policy, and a Python layer.

Usage
-----
# Full end-to-end (role, policy, function, code, layer, attach)
python deploy_lambda.py --config lambda_def.json --action full \
  --policy-file iam_secrets_policy.json --policy-name AllowReadProdSecrets

# Only update code package
python deploy_lambda.py --config lambda_def.json --action code

# Only rebuild/publish layer and attach it
python deploy_lambda.py --config lambda_def.json --action layer

# Add --debug to print AWS kwargs
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

PYTHON_VERSION = "3.13"
PLATFORM = "manylinux2014_x86_64"

# ---------------- Data model ----------------


@dataclass
class LayerDef:
    layer_name: str
    layer_type: str = "custom_layer"
    layer_packages: list[str] = field(default_factory=list)


@dataclass
class LambdaDef:
    function_name: str
    handler_name: str
    region_name: str
    runtime: str
    timeout: int
    memory_size: int
    role_name: str
    zip_filename: str
    code_files: list[str]
    layers: list[LayerDef] = field(default_factory=list)
    architecture: str = "x86_64"  # arm64 or x86_64
    description: str = ""
    environment: dict[str, str] = field(default_factory=dict)
    policy_name: str | None = None


# ---------------- Retry Helpers ----------------


def retry_with_backoff(
    func: Callable[..., Any],
    *args: Any,
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_multiplier: float = 2.0,
    **kwargs: Any,
) -> Any:
    """
    Retry a function with exponential backoff.

    Args:
        func: Function to retry
        *args: Positional arguments for the function
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        backoff_multiplier: Multiplier for exponential backoff
        **kwargs: Keyword arguments for the function

    Returns:
        The result of the function call

    Raises:
        The last exception if all retries are exhausted
    """
    last_exception: Exception | None = None
    delay = base_delay

    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt == max_retries:
                break

            print(f"Attempt {attempt + 1} failed: {e}")
            print(f"Retrying in {delay:.1f} seconds...")
            time.sleep(delay)
            delay = min(delay * backoff_multiplier, max_delay)

    if last_exception is not None:
        raise last_exception
    raise RuntimeError("Retry logic failed without exception")


def wait_for_policy_availability(iam: Any, policy_arn: str, max_retries: int = 10) -> None:
    """
    Wait for an IAM policy to become available for attachment.
    """

    def check_policy() -> bool:
        try:
            iam.get_policy(PolicyArn=policy_arn)
            return True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return False
            raise

    try:
        retry_with_backoff(check_policy, max_retries=max_retries, base_delay=2.0, max_delay=10.0)
        print(f"✅ Policy {policy_arn} is now available")
    except Exception as e:
        print(f"❌ Policy {policy_arn} not available after retries: {e}")
        raise


def wait_for_lambda_ready_for_layers(lmb: Any, function_name: str, max_retries: int = 10) -> None:
    """
    Wait for Lambda function to be ready for layer attachment.
    """

    def check_lambda_ready() -> bool:
        try:
            conf = lmb.get_function_configuration(FunctionName=function_name)
            state = conf.get("State")
            last_update = conf.get("LastUpdateStatus")

            # Function is ready if it's active and not updating
            if state == "Active" and last_update in ("Successful", "InProgress"):
                return True
            return False
        except ClientError:
            return False

    try:
        retry_with_backoff(
            check_lambda_ready, max_retries=max_retries, base_delay=3.0, max_delay=15.0
        )
        print(f"✅ Lambda function {function_name} is ready for layer attachment")
    except Exception as e:
        print(f"❌ Lambda function {function_name} not ready after retries: {e}")
        raise


# ---------------- Helpers ----------------


def read_config(path: str) -> LambdaDef:
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    layers = [LayerDef(**layer) for layer in cfg.get("layers", [])]
    return LambdaDef(
        function_name=cfg["function_name"],
        handler_name=cfg["handler_name"],
        region_name=cfg["region_name"],
        runtime=cfg["runtime"],
        timeout=int(cfg["timeout"]),
        memory_size=int(cfg["memory_size"]),
        role_name=cfg["role_name"],
        zip_filename=cfg.get("zip_filename", f"{cfg['function_name']}.zip"),
        code_files=cfg["code_files"],
        layers=layers,
        architecture=cfg.get("architecture", "x86_64"),
        description=cfg.get("description", ""),
        environment=cfg.get("environment", {}),
        policy_name=cfg.get("policy_name"),
    )


def zip_files(zip_path: Path, files: list[str]) -> None:
    """
    Create the deployment zip from a list of files.
    Special case: if 'infrastructure/platform_manager.py' is requested,
    zip 'infrastructure/aws_platform_manager.py' instead, but keep the
    arcname as 'infrastructure/platform_manager.py'.
    """
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    special_dest = "infrastructure/platform_manager.py"
    special_src = Path("infrastructure/aws_platform_manager.py")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in files:
            dest_arcname = str(Path(rel))
            # Special swap
            if dest_arcname == special_dest and special_src.exists():
                zf.write(special_src, arcname=dest_arcname)
                print(f"⚙️  Substituted '{special_src}' → '{dest_arcname}' in zip")
                continue

            fp = Path(rel)
            if not fp.exists():
                raise FileNotFoundError(f"Code file '{rel}' not found")
            zf.write(fp, arcname=dest_arcname)


def ensure_role(iam: Any, role_name: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Execution role for Lambda",
        )
        role_arn = str(resp["Role"]["Arn"])

        # Attach the basic execution policy
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )

        # Wait for the role to be ready for Lambda to assume it
        def check_role_ready() -> bool:
            try:
                # Try to get the role to ensure it exists and is accessible
                iam.get_role(RoleName=role_name)
                # Check if the basic execution policy is attached
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                basic_exec_policy_attached = any(
                    policy["PolicyArn"]
                    == "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    for policy in attached_policies.get("AttachedPolicies", [])
                )
                return basic_exec_policy_attached
            except ClientError:
                return False

        retry_with_backoff(check_role_ready, max_retries=10, base_delay=2.0, max_delay=10.0)

        print(f"Created role: {role_arn}")
        return str(role_arn)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
            role_arn = str(iam.get_role(RoleName=role_name)["Role"]["Arn"])
            print(f"Role exists: {role_arn}")
            return role_arn
        raise


def put_inline_policy(
    iam: Any, role_name: str, policy_name: str, policy_doc: dict[str, Any]
) -> None:
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    print(f"Attached inline policy '{policy_name}' to role '{role_name}'")


def attach_existing_policies(iam: Any, role_name: str, policy_names: list[str]) -> None:
    """
    Attach existing IAM policies to a role.
    Prints success/failure for each policy.
    """
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    for policy_name in policy_names:
        try:
            # First try as AWS managed policy
            aws_managed_arn = f"arn:aws:iam::aws:policy/{policy_name}"
            try:
                iam.get_policy(PolicyArn=aws_managed_arn)
                policy_arn = aws_managed_arn
            except ClientError:
                # If not found as AWS managed, try as customer-managed policy
                customer_managed_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
                iam.get_policy(PolicyArn=customer_managed_arn)
                policy_arn = customer_managed_arn

            # Wait for policy to be available before attaching
            wait_for_policy_availability(iam, policy_arn)

            # Attach the policy to the role with retry logic
            def attach_policy(arn: str = policy_arn) -> None:
                iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

            retry_with_backoff(attach_policy, max_retries=5, base_delay=2.0, max_delay=10.0)
            print(f"✅ Successfully attached policy '{policy_name}' to role '{role_name}'")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "NoSuchEntity":
                error_msg = (
                    f"❌ Policy '{policy_name}' not found in IAM "
                    "(checked both AWS managed and customer managed)"
                )
                print(error_msg)
            else:
                print(f"❌ Failed to attach policy '{policy_name}': {e}")
        except Exception as e:
            print(f"❌ Unexpected error attaching policy '{policy_name}': {e}")


def load_and_substitute_policy(policy_file: str) -> dict[str, Any]:
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    with open(policy_file, encoding="utf-8") as f:
        text = f.read()
    return dict(json.loads(text.replace("{aws_account_id}", account_id)))


def function_exists(lmb: Any, function_name: str) -> bool:
    try:
        lmb.get_function(FunctionName=function_name)
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("ResourceNotFoundException", "404"):
            return False
        raise


# --------- Waiter/poller to avoid ResourceConflictException ---------


def wait_for_lambda_ready(
    lmb: Any, function_name: str, *, timeout: int = 300, interval: float = 2.0
) -> None:
    """
    Wait until the function is no longer updating.
    Prefer official waiter; fall back to polling LastUpdateStatus/State.
    """
    try:
        waiter = lmb.get_waiter("function_updated")
        waiter.wait(
            FunctionName=function_name,
            WaiterConfig={"Delay": int(interval), "MaxAttempts": max(1, int(timeout / interval))},
        )
        return
    except Exception:
        pass

    end = time.time() + timeout
    last = state = None
    while time.time() < end:
        conf = lmb.get_function_configuration(FunctionName=function_name)
        state = conf.get("State")
        last = conf.get("LastUpdateStatus")
        if last in ("Successful", "Failed") and state not in ("Pending",):
            return
        time.sleep(interval)
    raise TimeoutError(
        f"Lambda '{function_name}' not ready after {timeout}s "
        + f"(State={state}, LastUpdateStatus={last})"
    )


# --------- Layer dedupe helpers (avoid two versions of same layer) ---------


def _layer_name_from_arn(layer_arn: str) -> str:
    """
    Extract layer name from an ARN like:
      arn:aws:lambda:REGION:ACCOUNT:layer:LayerName:VERSION
    """
    parts = layer_arn.split(":")
    return parts[-2] if len(parts) >= 2 else layer_arn


def _merge_layers(existing: list[str], new_arns: list[str]) -> list[str]:
    """
    Merge existing + new layer ARNs, dropping any older versions that share the same layer name
    as a newly published version.
    """
    new_names = {_layer_name_from_arn(a) for a in new_arns}
    kept_existing = [a for a in existing if _layer_name_from_arn(a) not in new_names]
    return kept_existing + new_arns


# ---------------- Lambda ops ----------------


def create_or_update_function(
    lmb: Any, cfg: LambdaDef, role_arn: str, code_zip: bytes, *, debug: bool = False
) -> None:
    arch = cfg.architecture
    if arch not in ("x86_64", "arm64"):
        raise ValueError("architecture must be 'x86_64' or 'arm64'")

    if not function_exists(lmb, cfg.function_name):
        print(f"Creating Lambda function: {cfg.function_name}")
        kwargs: dict[str, Any] = {
            "FunctionName": cfg.function_name,
            "Runtime": cfg.runtime,
            "Role": role_arn,
            "Handler": cfg.handler_name,
            "Code": {"ZipFile": code_zip},
            "Timeout": cfg.timeout,
            "MemorySize": cfg.memory_size,
            "Architectures": [arch],  # allowed on create
            "Publish": True,
        }
        if cfg.description:
            kwargs["Description"] = cfg.description
        if cfg.environment:
            kwargs["Environment"] = {"Variables": dict(cfg.environment)}
        if debug:
            printable = {k: ("<ZipFile>" if k == "Code" else v) for k, v in kwargs.items()}
            print("create_function kwargs:", json.dumps(printable, indent=2))
        lmb.create_function(**kwargs)
        wait_for_lambda_ready(lmb, cfg.function_name)
        print("Created.")
    else:
        print(f"Updating code for Lambda function: {cfg.function_name}")
        lmb.update_function_code(FunctionName=cfg.function_name, ZipFile=code_zip, Publish=True)
        wait_for_lambda_ready(lmb, cfg.function_name)
        print("Code updated.")


def update_function_configuration(
    lmb: Any,
    cfg: LambdaDef,
    role_arn: str | None = None,
    layer_arns: list[str] | None = None,
    *,
    debug: bool = False,
) -> None:
    """
    Update configuration (runtime, handler, timeout, memory, env, role, layers).
    'Architectures' is CREATE-ONLY and intentionally excluded.
    """
    # Ensure no prior update is in progress
    wait_for_lambda_ready(lmb, cfg.function_name)

    kwargs: dict[str, Any] = {
        "FunctionName": cfg.function_name,
        "Runtime": cfg.runtime,  # omit if you never want to bump runtime
        "Handler": cfg.handler_name,
        "Timeout": cfg.timeout,
        "MemorySize": cfg.memory_size,
    }
    if cfg.environment:
        kwargs["Environment"] = {"Variables": cfg.environment}
    if role_arn:
        kwargs["Role"] = role_arn
    if layer_arns is not None:
        kwargs["Layers"] = layer_arns

    # FINAL allow-list to prevent unsupported params slipping through
    allowed = {
        "FunctionName",
        "Role",
        "Handler",
        "Description",
        "Timeout",
        "MemorySize",
        "VpcConfig",
        "Environment",
        "Runtime",
        "DeadLetterConfig",
        "KMSKeyArn",
        "TracingConfig",
        "RevisionId",
        "Layers",
        "FileSystemConfigs",
        "ImageConfig",
        "EphemeralStorage",
        "SnapStart",
        "LoggingConfig",
    }
    kwargs = {k: v for k, v in kwargs.items() if k in allowed}

    print(f"Updating configuration for {cfg.function_name} …")
    if debug:
        print("update_function_configuration kwargs:", json.dumps(kwargs, indent=2))
    lmb.update_function_configuration(**kwargs)

    # Wait for this update to complete to avoid subsequent conflicts
    wait_for_lambda_ready(lmb, cfg.function_name)
    print("Configuration updated.")


def build_layer_zip(tmpdir: Path, packages: list[str]) -> Path:
    layer_root = tmpdir / "python"
    layer_root.mkdir(parents=True, exist_ok=True)
    if packages:
        cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--platform",
            PLATFORM,
            "--target",
            str(layer_root),
            "--implementation",
            "cp",
            "--python-version",
            PYTHON_VERSION,
            "--only-binary=:all:",
            "--upgrade",
            *packages,
        ]
        print("Installing layer packages:", " ".join(packages))
        subprocess.check_call(cmd)
    layer_zip = tmpdir / "layer.zip"
    with zipfile.ZipFile(layer_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in layer_root.rglob("*"):
            zf.write(p, arcname=str(p.relative_to(tmpdir)))
    print(f"Built layer at {layer_zip}")
    return layer_zip


def publish_layer(
    lmb: Any, layer_name: str, layer_zip_bytes: bytes, compatible_runtimes: list[str]
) -> str:
    resp = lmb.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": layer_zip_bytes},
        CompatibleRuntimes=compatible_runtimes,
    )
    arn = str(resp["LayerVersionArn"])
    print(f"Published layer version: {arn}")
    return arn


def get_existing_layers(lmb: Any, function_name: str) -> list[str]:
    try:
        conf = lmb.get_function_configuration(FunctionName=function_name)
        return [layer["Arn"] for layer in conf.get("Layers", [])]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("ResourceNotFoundException", "404"):
            return []
        raise


# ---------------- Main ----------------


def run() -> None:
    ap = argparse.ArgumentParser(description="Deploy Lambda, code, and layer per JSON definition.")
    ap.add_argument("--config", required=True, help="Path to JSON definition file")
    ap.add_argument(
        "--action",
        choices=["full", "code", "layer", "policy"],
        default="full",
        help=(
            "full: role+policy+function+code+layer; code: only code; layer: only layer (+attach); "
            "policy: only policy modifications [default: full]"
        ),
    )
    ap.add_argument(
        "--policy-file", help="Optional IAM policy JSON to add as inline policy to the role"
    )
    ap.add_argument(
        "--policy-name",
        default="AppInlinePolicy",
        help="Inline policy name (if --policy-file provided)",
    )
    ap.add_argument(
        "--attach-policy",
        nargs="+",
        help=(
            "One or more existing IAM policy names to attach to the role "
            "(e.g., --attach-policy AllowReadProdSecrets)"
        ),
    )
    ap.add_argument(
        "--replace-layers",
        action="store_true",
        help="When attaching new layer(s), replace existing ones instead of appending.",
    )
    ap.add_argument("--debug", action="store_true", help="Print AWS kwargs for troubleshooting.")
    args = ap.parse_args()

    cfg = read_config(args.config)
    iam = boto3.client("iam")
    lmb = boto3.client("lambda", region_name=cfg.region_name)

    # 1) Role (full only)
    role_arn = None
    if args.action == "full":
        role_arn = ensure_role(iam, cfg.role_name)
        if args.policy_file:
            doc = load_and_substitute_policy(args.policy_file)
            put_inline_policy(iam, cfg.role_name, args.policy_name, doc)
        if args.attach_policy:
            attach_existing_policies(iam, cfg.role_name, args.attach_policy)

        # Attach policy from config file if specified
        if cfg.policy_name:
            print(f"Attaching policy '{cfg.policy_name}' to role '{cfg.role_name}' from config")
            attach_existing_policies(iam, cfg.role_name, [cfg.policy_name])

        time.sleep(5)

    # 1.5) Policy modifications (policy action only)
    if args.action == "policy":
        if not function_exists(lmb, cfg.function_name):
            error_msg = (
                f"Function {cfg.function_name} does not exist; cannot modify policies. "
                f"Run --action full first to create the function."
            )
            raise RuntimeError(error_msg)
        print("Modifying policies for existing Lambda function...")
        if args.policy_file:
            doc = load_and_substitute_policy(args.policy_file)
            put_inline_policy(iam, cfg.role_name, args.policy_name, doc)
        if args.attach_policy:
            attach_existing_policies(iam, cfg.role_name, args.attach_policy)

        # Attach policy from config file if specified
        if cfg.policy_name:
            print(f"Attaching policy '{cfg.policy_name}' to role '{cfg.role_name}' from config")
            attach_existing_policies(iam, cfg.role_name, [cfg.policy_name])

        print("Policy modifications completed.")

    # 2) Code package
    if args.action in ("full", "code"):
        code_zip_path = Path(cfg.zip_filename).resolve()
        print(f"Zipping function code to: {code_zip_path}")
        zip_files(code_zip_path, cfg.code_files)
        with open(code_zip_path, "rb") as f:
            code_bytes = f.read()

        if args.action == "full":
            if role_arn is None:
                role_arn = iam.get_role(RoleName=cfg.role_name)["Role"]["Arn"]
            create_or_update_function(lmb, cfg, role_arn, code_bytes, debug=args.debug)
            # Keep config in sync (no Architectures here)
            update_function_configuration(
                lmb, cfg, role_arn=None, layer_arns=None, debug=args.debug
            )
        else:
            if not function_exists(lmb, cfg.function_name):
                raise RuntimeError(
                    f"Function {cfg.function_name} does not exist; run --action full first."
                )
            print("Updating function code only …")
            lmb.update_function_code(
                FunctionName=cfg.function_name, ZipFile=code_bytes, Publish=True
            )
            wait_for_lambda_ready(lmb, cfg.function_name)
            print("Code updated.")

    # 3) Layer build/publish/attach
    if args.action in ("full", "layer"):
        if not cfg.layers:
            print("No layers defined in config; skipping layer build/publish.")
        else:
            new_layer_arns: list[str] = []
            with tempfile.TemporaryDirectory() as td:
                tmpdir = Path(td)
                for layer_def in cfg.layers:
                    layer_zip = build_layer_zip(tmpdir, layer_def.layer_packages)
                    with open(layer_zip, "rb") as f:
                        layer_bytes = f.read()
                    arn = publish_layer(lmb, layer_def.layer_name, layer_bytes, [cfg.runtime])
                    new_layer_arns.append(arn)

            if not function_exists(lmb, cfg.function_name):
                raise RuntimeError(
                    f"Function {cfg.function_name} does not exist; cannot attach layer."
                )

            # Wait for Lambda function to be ready for layer attachment
            wait_for_lambda_ready_for_layers(lmb, cfg.function_name)

            existing = [] if args.replace_layers else get_existing_layers(lmb, cfg.function_name)
            layer_arns = (
                new_layer_arns if args.replace_layers else _merge_layers(existing, new_layer_arns)
            )

            # Attach layers with retry logic
            def attach_layers() -> None:
                update_function_configuration(
                    lmb, cfg, role_arn=None, layer_arns=layer_arns, debug=args.debug
                )

            retry_with_backoff(attach_layers, max_retries=5, base_delay=3.0, max_delay=15.0)
            print("Layer(s) attached.")
    else:
        print("Skipping layer processing (use action 'layer' or 'full' to process layers)")

    print("Done.")


if __name__ == "__main__":
    run()

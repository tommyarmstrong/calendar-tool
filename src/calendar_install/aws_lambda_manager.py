import argparse
import json
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import boto3
from aws_config_manager import AWSConfig, create_logger, get_config
from botocore.config import Config
from botocore.exceptions import ClientError

PLATFORM = "manylinux2014_x86_64"

logger = create_logger(logger_name="aws_deployment", log_level="INFO")


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


def zip_files(zip_path: Path, files: list[str]) -> None:
    """
    Create the deployment zip from a list of files.
    For each file in the files list, find it in the code_directory and
    preserve the relative structure inside the zip (e.g. app/main.py).
    Special case: if 'infrastructure/platform_manager.py' is requested,
    zip 'infrastructure/aws_platform_manager.py' instead, but keep the
    arcname as 'infrastructure/platform_manager.py'.
    """
    logger.debug(f"zip_path: {zip_path}")
    logger.debug(f"zip_path parent: {zip_path.parent}")

    code_directory = zip_path.parent
    logger.debug(f"code_directory: {code_directory}")
    logger.debug(f"code_directory absolute: {code_directory.absolute()}")
    logger.debug(f"code_directory exists: {code_directory.absolute().exists()}")

    code_directory.mkdir(parents=True, exist_ok=True)
    special_dest = "infrastructure/platform_manager.py"
    special_src = code_directory / "infrastructure/aws_platform_manager.py"

    # Map shared_infrastructure symlinked files to their real sources under src/calendar_shared
    shared_map = {
        "platform_manager.py": "aws_platform_manager.py",  # use AWS variant in Lambdas
        "redis_manager.py": "redis_manager.py",
        "hmac_auth.py": "hmac_auth.py",
        "cryptography_manager.py": "cryptography_manager.py",
    }

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_file in files:
            logger.debug(f"Processing file: {rel_file}")

            # Special swap: if requesting platform_manager.py, use aws_platform_manager.py instead
            if rel_file == special_dest and special_src.exists():
                zf.write(special_src, arcname=rel_file)
                logger.info(f"Substituted 'aws_platform_manager.py' → '{rel_file}' in zip")
                continue

            # Handle shared_infrastructure symlinks by copying real files from src/calendar_shared
            if rel_file.startswith("shared_infrastructure/"):
                name = rel_file.split("/", 1)[1]
                src_name = shared_map.get(name, name)
                shared_src = (code_directory.parent / "calendar_shared" / src_name).resolve()
                if shared_src.exists():
                    zf.write(shared_src, arcname=rel_file)
                    logger.info(f"Injected calendar_shared/{src_name} → {rel_file} in zip")
                    continue

            # Find the file in the code directory
            file_path = code_directory / rel_file
            logger.debug(f"Looking for file: {file_path.absolute()}")
            logger.debug(f"File exists: {file_path.exists()}")

            if not file_path.exists():
                raise FileNotFoundError(f"Code file '{rel_file}' not found in {code_directory}")

            # Write the file to zip with the same relative path structure
            zf.write(file_path, arcname=rel_file)
            logger.debug(f"Added '{rel_file}' to zip")


def load_code_bytes(zip_path: Path) -> bytes:
    with open(zip_path, "rb") as f:
        return f.read()


def build_layer_zip(*, tmpdir: Path, packages: list[str], python_version: str) -> Path:
    """
    Build a Lambda layer zip file with the specified packages.

    Args:
        tmpdir: Temporary directory for building the layer
        packages: List of Python packages to install
        python_version: Python version for compatibility

    Returns:
        Path to the built layer zip file
    """
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
            python_version,
            "--only-binary=:all:",
            "--upgrade",
            *packages,
        ]
        print("Installing layer packages:", " ".join(packages))
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            print(f"Failed to install packages: {e}")
            raise

    layer_zip = tmpdir / "layer.zip"
    with zipfile.ZipFile(layer_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in layer_root.rglob("*"):
            if p.is_file():  # Only add files, not directories
                zf.write(p, arcname=str(p.relative_to(tmpdir)))

    # Check layer size
    layer_size = layer_zip.stat().st_size
    layer_size_mb = layer_size / (1024 * 1024)
    print(f"Built layer at {layer_zip} (size: {layer_size_mb:.2f} MB)")

    # Warn if layer is getting large
    if layer_size_mb > 30:
        print(
            f"WARNING: Layer size ({layer_size_mb:.2f} MB) is large and may cause upload timeouts"
        )

    return layer_zip


class LambdaManager:
    def __init__(self, config: AWSConfig):
        self.config = config
        self.code_zip_path = Path(self.config.code_directory / self.config.zip_filename).resolve()

        # AWS clients with extended timeouts for large uploads
        self.iam_client = boto3.client("iam")
        self.lambda_client = boto3.client(
            "lambda",
            config=Config(
                read_timeout=300,  # 5 minutes
                connect_timeout=60,  # 1 minute
                retries={"max_attempts": 3},
            ),
        )

    def _function_exists(self) -> bool:
        try:
            self.lambda_client.get_function(FunctionName=self.config.function_name)
            return True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in (
                "ResourceNotFoundException",
                "404",
            ):
                return False
            raise

    def _wait_for_lambda_ready_for_layers(self, *, max_retries: int = 10) -> None:
        """
        Wait for Lambda function to be ready for layer attachment.
        """

        def check_lambda_ready() -> bool:
            try:
                conf = self.lambda_client.get_function_configuration(
                    FunctionName=self.config.function_name
                )
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
                check_lambda_ready,
                max_retries=max_retries,
                base_delay=3.0,
                max_delay=15.0,
            )
            logger.info(
                f"Lambda function {self.config.function_name} is ready for layer attachment"
            )
        except Exception as e:
            logger.error(
                f"Lambda function {self.config.function_name} not ready after retries: {e}"
            )
            raise

    def _wait_for_lambda_ready(self, *, timeout: int = 300, interval: float = 2.0) -> None:
        """
        Wait until the function is no longer updating.
        Prefer official waiter; fall back to polling LastUpdateStatus/State.
        """
        try:
            waiter = self.lambda_client.get_waiter("function_updated")
            waiter.wait(
                FunctionName=self.config.function_name,
                WaiterConfig={
                    "Delay": int(interval),
                    "MaxAttempts": max(1, int(timeout / interval)),
                },
            )
            return
        except Exception:
            pass

        end = time.time() + timeout
        last = state = None
        while time.time() < end:
            conf = self.lambda_client.get_function_configuration(
                FunctionName=self.config.function_name
            )
            state = conf.get("State")
            last = conf.get("LastUpdateStatus")
            if last in ("Successful", "Failed") and state not in ("Pending",):
                return
            time.sleep(interval)
        raise TimeoutError(
            f"Lambda '{self.config.function_name}' not ready after {timeout}s "
            + f"(State={state}, LastUpdateStatus={last})"
        )

    def _wait_for_policy_availability(self, policy_arn: str, max_retries: int = 10) -> None:
        """
        Wait for an IAM policy to become available for attachment.
        """

        def check_policy() -> bool:
            try:
                self.iam_client.get_policy(PolicyArn=policy_arn)
                return True
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                    return False
                raise

        try:
            retry_with_backoff(
                check_policy, max_retries=max_retries, base_delay=2.0, max_delay=10.0
            )
            logger.info(f"Policy {policy_arn} is available")
        except Exception as e:
            logger.error(f"Policy {policy_arn} not available after retries: {e}")
            raise

    def _attach_existing_policies(self, policy_names: list[str]) -> None:
        """
        Attach existing IAM policies to a role.
        Prints success/failure for each policy.
        """
        for policy_name in policy_names:
            try:
                # First try as AWS managed policy
                aws_managed_arn = f"arn:aws:iam::aws:policy/{policy_name}"
                try:
                    self.iam_client.get_policy(PolicyArn=aws_managed_arn)
                    policy_arn = aws_managed_arn
                except ClientError:
                    # If not found as AWS managed, try as customer-managed policy
                    customer_managed_arn = (
                        f"arn:aws:iam::{self.config.account_id}:policy/{policy_name}"
                    )
                    self.iam_client.get_policy(PolicyArn=customer_managed_arn)
                    policy_arn = customer_managed_arn

                # Wait for policy to be available before attaching
                self._wait_for_policy_availability(policy_arn)

                # Attach the policy to the role with retry logic
                def attach_policy(arn: str = policy_arn) -> None:
                    self.iam_client.attach_role_policy(
                        RoleName=self.config.role_name, PolicyArn=arn
                    )

                retry_with_backoff(attach_policy, max_retries=5, base_delay=2.0, max_delay=10.0)
                logger.info(
                    f"Successfully attached policy '{policy_name}' to role "
                    + f"'{self.config.role_name}'"
                )
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "NoSuchEntity":
                    logger.error(
                        f"Policy '{policy_name}' not found in IAM "
                        + "(checked both AWS managed and customer managed)"
                    )
                else:
                    logger.error(f"Failed to attach policy '{policy_name}': {e}")
            except Exception as e:
                logger.error(f"Unexpected error attaching policy '{policy_name}': {e}")

    def _ensure_role(self) -> str:
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

        # Create the role with the trust policy
        try:
            resp = self.iam_client.create_role(
                RoleName=self.config.role_name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Description="Execution role for Lambda",
            )
            role_arn = str(resp["Role"]["Arn"])

            # Attach the basic execution policy
            self.iam_client.attach_role_policy(
                RoleName=self.config.role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )

            # Wait for the role to be ready for Lambda to assume it
            def check_role_ready() -> bool:
                try:
                    # Try to get the role to ensure it exists and is accessible
                    self.iam_client.get_role(RoleName=self.config.role_name)
                    # Check if the basic execution policy is attached
                    attached_policies = self.iam_client.list_attached_role_policies(
                        RoleName=self.config.role_name
                    )
                    basic_exec_policy_attached = any(
                        policy["PolicyArn"]
                        == "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                        for policy in attached_policies.get("AttachedPolicies", [])
                    )
                    return basic_exec_policy_attached
                except ClientError:
                    return False

            retry_with_backoff(check_role_ready, max_retries=10, base_delay=2.0, max_delay=10.0)

            logger.info(f"Created role: {role_arn}")
            return str(role_arn)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                role_arn = str(
                    self.iam_client.get_role(RoleName=self.config.role_name)["Role"]["Arn"]
                )
                logger.info(f"Role exists: {role_arn}")
                return role_arn
            raise

    def _publish_layer(
        self,
        layer_name: str,
        layer_zip_bytes: bytes,
        compatible_runtimes: list[str] | str,
    ) -> str:
        """
        Publish a Lambda layer with retry logic for network timeouts.

        Args:
            layer_name: Name of the layer
            layer_zip_bytes: Layer zip file content as bytes
            compatible_runtimes: List of compatible Python runtimes

        Returns:
            Layer version ARN

        Raises:
            Exception: If layer publishing fails after all retries
        """
        if isinstance(compatible_runtimes, str):
            compatible_runtimes = [compatible_runtimes]

        # Log layer size for debugging
        layer_size_mb = len(layer_zip_bytes) / (1024 * 1024)
        logger.info(f"Publishing layer '{layer_name}' (size: {layer_size_mb:.2f} MB)")

        # Check if layer is too large (AWS limit is 250MB unzipped, 50MB zipped)
        if len(layer_zip_bytes) > 50 * 1024 * 1024:  # 50MB
            raise ValueError(f"Layer zip file is too large: {layer_size_mb:.2f} MB (max: 50MB)")

        def publish_layer_with_retry() -> str:
            try:
                resp = self.lambda_client.publish_layer_version(
                    LayerName=layer_name,
                    Content={"ZipFile": layer_zip_bytes},
                    CompatibleRuntimes=compatible_runtimes,
                )
                arn = str(resp["LayerVersionArn"])
                logger.info(f"Published layer version: {arn}")
                return arn
            except Exception as e:
                logger.error(f"Failed to publish layer '{layer_name}': {e}")
                raise

        # Use retry logic for network timeouts and connection issues
        try:
            arn = retry_with_backoff(
                publish_layer_with_retry,
                max_retries=3,
                base_delay=5.0,
                max_delay=30.0,
                backoff_multiplier=2.0,
            )
            return str(arn)
        except Exception as e:
            logger.error(f"Failed to publish layer '{layer_name}' after retries: {e}")
            raise

    def _get_existing_layers(self) -> list[str]:
        try:
            conf = self.lambda_client.get_function_configuration(
                FunctionName=self.config.function_name
            )
            return [layer["Arn"] for layer in conf.get("Layers", [])]
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in (
                "ResourceNotFoundException",
                "404",
            ):
                return []
            raise

    def _layer_name_from_arn(self, layer_arn: str) -> str:
        """
        Extract layer name from an ARN like:
        arn:aws:lambda:REGION:ACCOUNT:layer:LayerName:VERSION
        """
        parts = layer_arn.split(":")
        return parts[-2] if len(parts) >= 2 else layer_arn

    def _merge_layers(self, existing: list[str], new_arns: list[str]) -> list[str]:
        """
        Merge existing + new layer ARNs, dropping any older versions that share the same layer name
        as a newly published version.
        """
        new_names = {self._layer_name_from_arn(a) for a in new_arns}
        kept_existing = [a for a in existing if self._layer_name_from_arn(a) not in new_names]
        return kept_existing + new_arns

    def _update_function_configuration(
        self,
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
        self._wait_for_lambda_ready()

        kwargs: dict[str, Any] = {
            "FunctionName": self.config.function_name,
            "Runtime": self.config.runtime,
            "Handler": self.config.handler_name,
            "Timeout": self.config.timeout,
            "MemorySize": self.config.memory_size,
        }
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

        logger.info(f"Updating configuration for {self.config.function_name} …")
        logger.debug("update_function_configuration kwargs:", json.dumps(kwargs, indent=2))
        self.lambda_client.update_function_configuration(**kwargs)

        # Wait for this update to complete to avoid subsequent conflicts
        self._wait_for_lambda_ready()
        logger.info("Configuration updated.")

    def create_function(self, *, debug: bool = False) -> None:
        arch = self.config.architecture
        if arch not in ("x86_64", "arm64"):
            raise ValueError("architecture must be 'x86_64' or 'arm64'")

        # Load the code bytes from the zip file
        code_zip_bytes = load_code_bytes(self.code_zip_path)

        # Deploy the role if it doesn't exist
        self.deploy_role() if not self.role_arn else None

        # Create or update the function
        if not self._function_exists():
            logger.info(f"Creating Lambda function: {self.config.function_name}")
            kwargs: dict[str, Any] = {
                "FunctionName": self.config.function_name,
                "Runtime": self.config.runtime,
                "Role": self.role_arn,
                "Handler": self.config.handler_name,
                "Code": {"ZipFile": code_zip_bytes},
                "Timeout": self.config.timeout,
                "MemorySize": self.config.memory_size,
                "Architectures": [arch],  # allowed on create
                "Publish": True,
            }
            if debug:
                printable = {k: ("<ZipFile>" if k == "Code" else v) for k, v in kwargs.items()}
                logger.info("create_function kwargs:", json.dumps(printable, indent=2))
            self.lambda_client.create_function(**kwargs)
            self._wait_for_lambda_ready()
            logger.info("Function created.")

        else:
            logger.info(
                f"Lambda function {self.config.function_name} already exists. "
                + "Updating configuration and code."
            )

            # Update function configuration
            self._update_function_configuration(role_arn=self.role_arn)

            # Update function code
            logger.info("Updating Lambda code...")
            self.lambda_client.update_function_code(
                FunctionName=self.config.function_name,
                ZipFile=code_zip_bytes,
                Publish=True,
            )
            self._wait_for_lambda_ready()
            logger.info("Function updated.")

    def deploy_role(self) -> None:
        logger.info("Deploying Lambda role")
        self.role_arn = self._ensure_role()

        # TODO: Attach policy inline policies, if specified

        # Attach policy from config file if specified
        if self.config.policy_name:
            logger.info(
                f"Attaching policy '{self.config.policy_name}' to role '{self.config.role_name}'"
            )
            # TODO: Attach multiple policies, if specified
            policy_list = [self.config.policy_name]
            self._attach_existing_policies(policy_list)

    def package_code(self) -> None:
        logger.info("Packaging Lambda code")

        logger.info(f"Zipping function code to: {self.code_zip_path}")
        zip_files(self.code_zip_path, self.config.code_files)

    def update_code(self) -> None:
        logger.info("Updating Lambda code...")

        self.package_code()
        code_bytes = load_code_bytes(self.code_zip_path)
        self.lambda_client.update_function_code(
            FunctionName=self.config.function_name,
            ZipFile=code_bytes,
            Publish=True,
        )
        self._wait_for_lambda_ready()
        logger.info("Code updated.")

    def deploy_layers(
        self, *, replace_layers: bool = True, skip_large_layers: bool = False
    ) -> None:
        """
        Deploy Lambda layers with optional skipping of large layers.

        Args:
            replace_layers: Whether to replace existing layers
            skip_large_layers: Whether to skip layers that are too large (>30MB)
        """
        logger.info("Deploying Lambda layers")

        if not self.config.layers:
            logger.info("No layers defined.")
            return

        # Wait for Lambda function to be ready for layer attachment
        self._wait_for_lambda_ready_for_layers()

        # Build and publish layers
        new_layer_arns: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            for layer_def in self.config.layers:
                try:
                    python_version = self.config.runtime.replace("python", "")
                    layer_zip = build_layer_zip(
                        tmpdir=tmpdir,
                        packages=layer_def.layer_packages,
                        python_version=python_version,
                    )

                    # Check layer size and skip if too large
                    layer_size = layer_zip.stat().st_size
                    layer_size_mb = layer_size / (1024 * 1024)

                    if skip_large_layers and layer_size_mb > 30:
                        logger.warning(
                            f"Skipping layer '{layer_def.layer_name}' due to size: "
                            + f"{layer_size_mb:.2f} MB"
                        )
                        continue

                    with open(layer_zip, "rb") as f:
                        layer_bytes = f.read()

                    # Log final layer size before upload
                    final_size_mb = len(layer_bytes) / (1024 * 1024)
                    logger.info(
                        f"Final layer '{layer_def.layer_name}' size: {final_size_mb:.2f} MB"
                    )

                    arn = self._publish_layer(
                        layer_def.layer_name, layer_bytes, self.config.runtime
                    )
                    new_layer_arns.append(arn)

                except Exception as e:
                    logger.error(f"Failed to build/publish layer '{layer_def.layer_name}': {e}")
                    if not skip_large_layers:
                        raise
                    else:
                        logger.warning(f"Skipping layer '{layer_def.layer_name}' due to error: {e}")
                        continue

        if not new_layer_arns:
            logger.warning("No layers were successfully built/published")
            return

        existing = [] if replace_layers else self._get_existing_layers()
        layer_arns = (
            new_layer_arns if replace_layers else self._merge_layers(existing, new_layer_arns)
        )

        # Attach layers with retry logic
        def attach_layers() -> None:
            self._update_function_configuration(role_arn=None, layer_arns=layer_arns)

        retry_with_backoff(attach_layers, max_retries=5, base_delay=3.0, max_delay=15.0)
        logger.info("Layer(s) attached.")

    def deploy(self) -> None:
        logger.info("Deploying Lambda function")
        self.deploy_role()
        self.package_code()
        self.create_function()  # <-- Uploads code too
        self.deploy_layers()


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Deploy Lambda, code, and layer per JSON definition.")
    ap.add_argument("--config-file", "-c", required=True, help="Path to JSON definition file")
    ap.add_argument(
        "--action",
        choices=["full", "code", "layer"],
        default="full",
        help=(
            "full: configures the role, function, code and layer; "
            "code: only code update; "
            "layer: only layer update, Default: full"
        ),
    )
    ap.add_argument(
        "--replace-layers",
        action="store_true",
        help="When attaching new layer(s), replace existing ones instead of appending.",
    )
    ap.add_argument(
        "--skip-large-layers",
        action="store_true",
        help="Skip layers that are larger than 30MB to avoid upload timeouts.",
    )
    ap.add_argument("--debug", action="store_true", help="Print AWS kwargs for troubleshooting.")
    args = ap.parse_args()
    return args


def main() -> None:
    args = parse_args()

    config_file = args.config_file
    config = get_config(config_file)
    lambda_manager = LambdaManager(config)

    if args.action == "full":
        lambda_manager.deploy()

    elif args.action == "code":
        lambda_manager.update_code()

    elif args.action == "layer":
        lambda_manager.deploy_layers(
            replace_layers=args.replace_layers, skip_large_layers=args.skip_large_layers
        )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Gimlet CLI - JWT management and operations."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from . import jwt as jwt_utils


def _validate_signing_key_options(private_key_file: Path | None, kms_key_arn: str | None) -> None:
    """Validate that exactly one signing key option is provided."""
    has_private_key = bool(private_key_file)
    has_kms = bool(kms_key_arn)

    if has_private_key and has_kms:
        click.echo("Error: --private-key-file and --kms-key-arn are mutually exclusive", err=True)
        sys.exit(1)

    if not has_private_key and not has_kms:
        click.echo(
            "Error: Either --private-key-file or --kms-key-arn must be provided",
            err=True,
        )
        sys.exit(1)


@click.group()
def cli():
    """Gimlet - Distributed tunnel-based model serving."""
    pass


@cli.group()
def jwt():
    """JWT management commands."""
    pass


@jwt.command()
@click.option("--subject", required=True, help="Agent ID (used as sub claim)")
@click.option("--service", required=True, help="Service name to register for")
@click.option("--duration", default="24h", help="Token lifetime (e.g., 24h, 1d)")
@click.option(
    "--private-key-file",
    type=Path,
    envvar="GIMLET_JWT_PRIVATE_KEY_FILE",
    help="Private key file path for signing (env: GIMLET_JWT_PRIVATE_KEY_FILE)",
)
@click.option(
    "--kms-key-arn",
    envvar="GIMLET_JWT_KMS_KEY_ARN",
    help="AWS KMS key ARN for signing (env: GIMLET_JWT_KMS_KEY_ARN)",
)
@click.option(
    "--issuer",
    default="gimlet",
    envvar="GIMLET_JWT_ISSUER",
    help="JWT issuer claim (env: GIMLET_JWT_ISSUER)",
)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def agent(subject, service, duration, private_key_file, kms_key_arn, issuer, json_output):
    """Generate agent registration JWT (aud: gimlet-agent)."""
    _validate_signing_key_options(private_key_file, kms_key_arn)

    if kms_key_arn:
        token = jwt_utils.generate_agent_jwt_kms(subject, service, duration, kms_key_arn, issuer)
    else:
        token = jwt_utils.generate_agent_jwt(subject, service, duration, private_key_file, issuer)

    if json_output:
        exp = datetime.now(timezone.utc) + jwt_utils.parse_duration(duration)
        output = {
            "token": token,
            "subject": subject,
            "service": service,
            "audience": "gimlet-agent",
            "issuer": issuer,
            "duration": duration,
            "expires_at": exp.isoformat(),
        }
        if kms_key_arn:
            output["signing_key"] = kms_key_arn
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(token, nl=False)


@jwt.command()
@click.option("--subject", required=True, help="Client/user ID (used as sub claim)")
@click.option(
    "--services",
    required=True,
    help='Comma-separated service names or wildcards (e.g., "model-*,embedding-*" or "*")',
)
@click.option("--duration", default="24h", help="Token lifetime (e.g., 24h, 1d)")
@click.option(
    "--private-key-file",
    type=Path,
    envvar="GIMLET_JWT_PRIVATE_KEY_FILE",
    help="Private key file path for signing (env: GIMLET_JWT_PRIVATE_KEY_FILE)",
)
@click.option(
    "--kms-key-arn",
    envvar="GIMLET_JWT_KMS_KEY_ARN",
    help="AWS KMS key ARN for signing (env: GIMLET_JWT_KMS_KEY_ARN)",
)
@click.option(
    "--issuer",
    default="gimlet",
    envvar="GIMLET_JWT_ISSUER",
    help="JWT issuer claim (env: GIMLET_JWT_ISSUER)",
)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def client(subject, services, duration, private_key_file, kms_key_arn, issuer, json_output):
    """Generate client request JWT (aud: gimlet-client)."""
    _validate_signing_key_options(private_key_file, kms_key_arn)

    service_list = [s.strip() for s in services.split(",")]

    if kms_key_arn:
        token = jwt_utils.generate_client_jwt_kms(
            subject, service_list, duration, kms_key_arn, issuer
        )
    else:
        token = jwt_utils.generate_client_jwt(subject, service_list, duration, private_key_file, issuer)

    if json_output:
        exp = datetime.now(timezone.utc) + jwt_utils.parse_duration(duration)
        output = {
            "token": token,
            "subject": subject,
            "services": service_list,
            "audience": "gimlet-client",
            "issuer": issuer,
            "duration": duration,
            "expires_at": exp.isoformat(),
        }
        if kms_key_arn:
            output["signing_key"] = kms_key_arn
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(token, nl=False)


@jwt.command()
@click.argument("token", required=False)
@click.option("--verify", is_flag=True, help="Verify signature")
@click.option("--public-key", type=Path, help="Public key for verification")
def inspect(token, verify, public_key):
    """Inspect JWT (reads from stdin if no token provided)."""
    if not token:
        token = sys.stdin.read().strip()

    loaded_public_key = None
    if verify:
        if not public_key:
            click.echo("Error: --public-key required for verification", err=True)
            sys.exit(1)
        loaded_public_key = jwt_utils.load_public_key(public_key)

    try:
        claims = jwt_utils.decode_jwt(token, verify=verify, public_key=loaded_public_key)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Format output
    if verify:
        click.echo("✓ Signature verified\n")
    else:
        click.echo("⚠ Signature not verified\n")

    click.echo("Claims:")
    for k, v in claims.items():
        if k in ["exp", "iat", "nbf"]:
            dt = datetime.fromtimestamp(v, tz=timezone.utc)
            status = ""
            if k == "exp":
                status = (
                    " (EXPIRED)"
                    if dt < datetime.now(timezone.utc)
                    else f" (expires in {dt - datetime.now(timezone.utc)})"
                )
            click.echo(f"  {k}: {dt.isoformat()}{status}")
        else:
            click.echo(f"  {k}: {v}")


@jwt.command("export-public-key")
@click.option(
    "--kms-key-arn",
    required=True,
    envvar="GIMLET_JWT_KMS_KEY_ARN",
    help="AWS KMS key ARN (env: GIMLET_JWT_KMS_KEY_ARN)",
)
@click.option(
    "--output",
    "-o",
    type=Path,
    help="Output file path (default: stdout)",
)
def export_public_key(kms_key_arn, output):
    """Export public key from AWS KMS in PEM format."""
    try:
        public_key_pem = jwt_utils.get_kms_public_key(kms_key_arn)
    except Exception as e:
        click.echo(f"Error getting public key from KMS: {e}", err=True)
        sys.exit(1)

    if output:
        output.write_bytes(public_key_pem)
        click.echo(f"Public key written to {output}", err=True)
    else:
        click.echo(public_key_pem.decode("utf-8"), nl=False)


if __name__ == "__main__":
    cli()

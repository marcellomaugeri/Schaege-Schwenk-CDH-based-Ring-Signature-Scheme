"""Create a ring, sign a message and verify the signature."""

import typer

from schaege_schwenk_ring_signature import SSRingSignatureScheme

app = typer.Typer(add_completion=False)


@app.command()
def main(
    pairing_type: str = typer.Option(..., "--type", help="Pairing type: a or e."),
    rbits: int = typer.Option(..., min=3, help="Subgroup-order length in bits."),
    qbits: int = typer.Option(..., min=1, help="Base-field modulus length in bits."),
    hash_name: str = typer.Option("sha256", "--hash", help="Hashlib algorithm name."),
    users: int = typer.Option(5, min=1, help="Number of ring members."),
    signer: int = typer.Option(0, min=0, help="Zero-based signer position."),
    message: str = typer.Option("Hello", help="Message to sign."),
    precompute: bool = typer.Option(False, help="Precompute generator exponentiation."),
):
    """Demonstrate signing and verification with caller-selected pairing parameters."""
    if signer >= users:
        raise typer.BadParameter("must be smaller than --users", param_hint="--signer")
    try:
        scheme = SSRingSignatureScheme.setup(
            pairing_type,
            rbits,
            qbits,
            hash_name=hash_name,
            precompute=precompute,
        )
    except (ValueError, RuntimeError) as error:
        raise typer.BadParameter(str(error)) from error
    keys = scheme.keygen(users)
    ring = tuple(key.public_key for key in keys)
    payload = message.encode("utf-8")
    signature = scheme.sign(payload, ring, keys[signer].secret_key, signer)
    valid = scheme.verify(payload, ring, signature)
    modified = scheme.verify(payload + b"\x00", ring, signature)
    typer.echo(
        f"Ring members: {users}; signature components: {len(signature.components)}"
    )
    typer.echo(f"Valid signature: {valid}")
    typer.echo(f"Modified message accepted: {modified}")
    if not valid or modified:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

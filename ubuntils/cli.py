import click
from ubuntils import __version__


@click.group()
def main():
    """ubuntils - Ubuntu incident response tool."""
    pass


@main.command()
@click.option("--json", "output_json", is_flag=True, help="Output JSON instead of launching TUI")
@click.option("--remediate", is_flag=True, help="Run remediation engine after detection")
@click.option("--confirm", is_flag=True, help="Required with --remediate to apply changes")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def scan(output_json, remediate, confirm, verbose):
    """Scan the system for forensic artifacts and suspicious activity."""
    pass


@main.command()
def version():
    """Print version and exit."""
    click.echo(__version__)


if __name__ == "__main__":
    main()

from datetime import datetime, timezone
from pathlib import Path
import typer
from huginn.collectors.subdomains import CrtShCollector, CrtShError
from huginn.collectors.dns import DnsCollector
from huginn.collectors.whois import WhoisCollector, WhoisError
from huginn.collectors.emails import EmailCollector
from huginn.core.models import ScanResult
from huginn.output.json_writer import write_json

app = typer.Typer(help="Huginn - Passive OSINT recon tool")

@app.callback()
def main():
    """
    Huginn is a passive OSINT recon tool that collects information about a target domain.
    It uses various collectors to gather data and provides the results in a structured format.
    """
    pass

@app.command()
def subdomains(
    target: str = typer.Argument(..., help="Target domain, ex: example.com"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path (JSON)"),
):
    collector = CrtShCollector()
    try:
        findings = collector.collect(target)
    except CrtShError as exc:
        typer.echo(f"[!] {exc}", err=True)
        raise typer.Exit(code=1)

    result = ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    for f in findings:
        typer.echo(f.value)
    typer.echo(f"\n[+] {len(findings)} subdomains found for {target}")

    if output:
        write_json(result, output)
        typer.echo(f"[+] saved results to {output}")



@app.command()
def dns(
    target: str = typer.Argument(..., help="Target domain, ex: example.com"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path (JSON)"),
):
    collector = DnsCollector()
    findings = collector.collect(target)

    result = ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    for f in findings:
        typer.echo(f"[{f.metadata['record_type']}] {f.value}")
    typer.echo(f"\n [+] {len(findings)} DNS records found for {target}")

    if output:
        write_json(result, output)
        typer.echo(f"[+] saved results to {output}")


@app.command()
def whois(
    target: str = typer.Argument(..., help="Target domain, ex: example.com"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path (JSON)"),
):
    collector = WhoisCollector()
    try:
        findings = collector.collect(target)
    except WhoisError as exc:
        typer.echo(f"[!] {exc}", err=True)
        raise typer.Exit(code=1)

    result = ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    for f in findings:
        typer.echo(f"[{f.metadata['field']}] {f.value}")
    typer.echo(f"\n[+] {len(findings)} WHOIS fields found for {target}")

    if output:
        write_json(result, output)
        typer.echo(f"[+] saved results to {output}")


@app.command()
def emails(
    target: str = typer.Argument(..., help="Target domain, ex: example.com"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path (JSON)")
):
    collector = EmailCollector()
    findings = collector.collect(target)

    result = ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    for f in findings:
        typer.echo(f.value)
    typer.echo(f"\n[+] {len(findings)} emails found for {target}")

    if output:
        write_json(result, output)
        typer.echo(f"[+] saved results to {output}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain, ex: example.com"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path (JSON)"),
):
    
    collectors = [CrtShCollector(), DnsCollector(), WhoisCollector(), EmailCollector()]
    findings = []

    for collector in  collectors:
        try:
            findings.extend(collector.collect(target))
        except CrtShError as exc:
            typer.echo(f"[!] {collector.name}: {exc}", err=True)

    result = ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    for f in findings:
        typer.echo(f"[{f.source}] {f.value}")
    typer.echo(f"\n[+] {len(findings)} findings found for {target}")

    if output:
        write_json(result, output)
        typer.echo(f"[+] saved results to {output}")

if __name__ == "__main__":
    app()
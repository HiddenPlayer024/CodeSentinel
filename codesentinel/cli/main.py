import typer
from rich.console import Console
from rich.table import Table

from enum import Enum
from pathlib import Path

from codesentinel.core.scanner import Scanner
from codesentinel.reporting import JsonReporter, SarifReporter, HtmlReporter

app = typer.Typer(help="CodeSentinel: AI-Assisted Application Security Scanner")
console = Console()

class OutputFormat(str, Enum):
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"

@app.callback()
def callback():
    """
    CodeSentinel security scanner.
    """
    pass

@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind the API to"),
    port: int = typer.Option(8000, "--port", help="Port to bind the API to"),
):
    """
    Launch the CodeSentinel REST API server.
    """
    import uvicorn
    console.print(f"[bold green]Starting CodeSentinel API on http://{host}:{port}[/bold green]")
    uvicorn.run("codesentinel.api.main:app", host=host, port=port, reload=True)

@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to the directory or file to scan"),
    format: OutputFormat = typer.Option(OutputFormat.TERMINAL, "--format", "-f", help="Output format"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path (required for json/sarif/html)"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI-assisted verification"),
    ai_provider: str = typer.Option("mock", "--ai-provider", help="AI provider (mock, ollama, openai)"),
    ai_mode: str = typer.Option("hybrid", "--ai-mode", help="AI mode (verify, discover, hybrid)"),
    ai_max_files: int = typer.Option(None, "--ai-max-files", help="Maximum files for AI to analyze"),
    ai_max_review_units: int = typer.Option(None, "--ai-max-review-units", help="Maximum review units"),
    ai_max_findings: int = typer.Option(None, "--ai-max-findings", help="Maximum total AI findings"),
    fail_on: str = typer.Option("LOW", "--fail-on", help="Minimum severity to exit with non-zero status (INFO, LOW, MEDIUM, HIGH, CRITICAL)"),
):
    """
    Scan a repository for security vulnerabilities.
    """
    import codesentinel.config as config
    if ai_max_files is not None:
        config.AI_MAX_FILES = ai_max_files
    if ai_max_review_units is not None:
        config.AI_MAX_REVIEW_UNITS = ai_max_review_units
    if ai_max_findings is not None:
        config.AI_MAX_TOTAL_AI_FINDINGS = ai_max_findings
    
    console.print(f"[bold blue]CodeSentinel initializing scan on:[/bold blue] {target}")
    
    try:
        scanner = Scanner(target_path=target)
        session = scanner.run_scan()
        
        # Display the results
        table = Table(title="Scan Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Repository", session.project.path)
        table.add_row("Files Analyzed", str(session.project.file_count))
        table.add_row("Languages Detected", ", ".join(session.project.languages) if session.project.languages else "None")
        table.add_row("Duration", f"{session.duration_seconds:.2f}s")
        
        console.print(table)
        
        if session.project.file_count == 0:
            console.print("[yellow]Warning: No scannable files found.[/yellow]")
            raise typer.Exit(code=0)
            
        # --- PHASE 6: AI Verification and Discovery ---
        if ai:
            console.print(f"[bold blue]Running AI ({ai_mode}) via {ai_provider}...[/bold blue]")
            from codesentinel.ai.providers import MockProvider, OllamaProvider, OpenAICompatibleProvider
            from codesentinel.ai.discovery import AIDiscoveryEngine
            from codesentinel.ai.verifier import AIVerifier
            from codesentinel.analysis.correlator import Correlator
            
            if ai_provider == "mock":
                provider = MockProvider()
            elif ai_provider == "ollama":
                provider = OllamaProvider()
            elif ai_provider == "openai":
                provider = OpenAICompatibleProvider()
            else:
                console.print(f"[bold red]Error:[/bold red] Unknown AI provider '{ai_provider}'")
                raise typer.Exit(code=2)
                
            session.ai_enabled = True
            session.ai_mode = ai_mode
            session.ai_provider = ai_provider
            
            static_findings = session.findings
            discovered_findings = []
            
            if ai_mode in ["discover", "hybrid"]:
                discovery_engine = AIDiscoveryEngine(provider=provider, project_path=target)
                discovered_findings = discovery_engine.run_discovery(session)
                
                if ai_mode == "discover":
                    session.findings = discovered_findings
                else:
                    correlator = Correlator()
                    session.findings = correlator.correlate(static_findings, discovered_findings)
                    
            if ai_mode in ["verify", "hybrid"]:
                verifier = AIVerifier(provider=provider)
                verifier.verify_session(session)
                
            session.static_findings_count = len(static_findings)
            session.ai_findings_count = len(discovered_findings)
            session.verified_findings_count = sum(1 for f in session.findings if "ai-verified" in f.analysis_source)

            console.print("[bold green]AI processing complete.[/bold green]")
            
            ai_table = Table(title="AI Telemetry")
            ai_table.add_column("Metric", style="cyan")
            ai_table.add_column("Value", style="magenta")
            ai_table.add_row("Candidates", str(session.ai_candidate_findings))
            ai_table.add_row("Validated", str(session.ai_valid_findings))
            ai_table.add_row("Rejected", str(session.ai_rejected_findings))
            ai_table.add_row("AI-Added", str(session.ai_added_findings))
            ai_table.add_row("Correlated", str(session.ai_correlated_findings))
            ai_table.add_row("Duplicates", str(session.ai_duplicate_findings))
            ai_table.add_row("Provider Errors", str(session.ai_provider_errors))
            console.print(ai_table)

        # --- Determine Exit Code ---
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        fail_threshold = severity_rank.get(fail_on.upper(), 1)
        
        has_failing_findings = any(
            severity_rank.get(f.severity.value, 0) >= fail_threshold 
            for f in session.findings
        )
        exit_code = 1 if has_failing_findings else 0

        # --- PHASE 5: Reporting ---
        if format != OutputFormat.TERMINAL:
            if not output:
                console.print("[bold red]Error:[/bold red] --output is required when --format is not terminal")
                raise typer.Exit(code=2)
                
            out_path = Path(output)
            if format == OutputFormat.JSON:
                JsonReporter().generate(session, out_path)
            elif format == OutputFormat.SARIF:
                SarifReporter().generate(session, out_path)
            elif format == OutputFormat.HTML:
                HtmlReporter().generate(session, out_path)
                
            console.print(f"[bold green]Report successfully written to {output}[/bold green]")
            raise typer.Exit(code=exit_code)

        # Terminal format (Default)
        if session.findings:
            console.print(f"\n[bold red]Security Findings ({len(session.findings)}):[/bold red]")
            for f in session.findings:
                console.print(f"\n[bold yellow][{f.severity.value}][/bold yellow] {f.title}")
                console.print(f"  [bold]File:[/bold] {f.file}:{f.line_start}")
                console.print(f"  [bold]Code:[/bold] {f.evidence.snippet}")
                console.print(f"  [bold]Conf:[/bold] {f.confidence*100:.0f}% | [bold]Rule:[/bold] {f.rule_id}")
                console.print(f"  [bold]Why :[/bold] {f.description}")
                if f.ai_assessment:
                    ai_title = "[AI ANALYSIS]" if f.ai_assessment.is_likely_vulnerable else "[AI NOTE - Likely False Positive]"
                    ai_text = f.ai_assessment.explanation if f.ai_assessment.is_likely_vulnerable else f.ai_assessment.false_positive_reason
                    console.print(f"  [bold blue]{ai_title}:[/bold blue] {ai_text}")
                console.print(f"  [bold]Fix :[/bold] {f.remediation_text}")
                
            if not has_failing_findings:
                console.print(f"\n[bold green]Scan completed. Findings found, but none meet the failure threshold ({fail_on}).[/bold green]")
            raise typer.Exit(code=exit_code)
        else:
            console.print("\n[bold green]No vulnerabilities found! Scan successful.[/bold green]")
            raise typer.Exit(code=0)
    except typer.Exit:
        raise
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=2)
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=2)

if __name__ == "__main__":
    app()

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

baseline_app = typer.Typer(help="Manage baselines")
app.add_typer(baseline_app, name="baseline")

@baseline_app.command("create")
def baseline_create(
    target: str = typer.Argument(..., help="Path to the directory or file to scan"),
    output: str = typer.Option("baseline.json", "--output", "-o", help="Output file path for the baseline"),
):
    """
    Create a baseline from a scan.
    """
    console.print(f"[bold blue]Creating baseline from scan on:[/bold blue] {target}")
    try:
        scanner = Scanner(target_path=target)
        session = scanner.run_scan()
        from codesentinel.baseline import Baseline
        baseline = Baseline(output)
        baseline.save(session.findings)
        console.print(f"[bold green]Baseline successfully created and saved to {output}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error creating baseline:[/bold red] {e}")
        raise typer.Exit(code=2)


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
    changed: bool = typer.Option(False, "--changed", help="Enable incremental scan"),
    base: str = typer.Option("HEAD~1", "--base", help="Git base ref for incremental scan"),
    head: str = typer.Option("HEAD", "--head", help="Git head ref for incremental scan"),
    baseline_file: str = typer.Option(None, "--baseline", help="Path to baseline file"),
    policy_file: str = typer.Option(None, "--policy", help="Path to policy file"),
):
    """
    Scan a repository for security vulnerabilities.
    """
    from codesentinel.config import settings
    if ai_max_files is not None:
        settings.AI_MAX_FILES = ai_max_files
    if ai_max_review_units is not None:
        settings.AI_MAX_REVIEW_UNITS = ai_max_review_units
    if ai_max_findings is not None:
        settings.AI_MAX_TOTAL_AI_FINDINGS = ai_max_findings
    
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
                import os, json
                fixtures = json.loads(os.environ.get("MOCK_FIXTURES", "{}"))
                provider = MockProvider(fixtures=fixtures)
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
                    session.findings = correlator.correlate(session, static_findings, discovered_findings)
                    
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

        # --- PHASE 7: Baseline & Incremental ---
        from codesentinel.baseline import Baseline
        from codesentinel.analysis.incremental import parse_git_diff, categorize_findings
        from codesentinel.policy import Policy
        
        new_findings = session.findings
        all_findings = session.findings
        
        if baseline_file:
            console.print(f"[bold blue]Applying baseline:[/bold blue] {baseline_file}")
            baseline = Baseline(baseline_file)
            baseline.load()
            all_findings = baseline.apply(all_findings)
            new_findings = all_findings
            session.findings = all_findings
            
        if changed:
            console.print(f"[bold blue]Incremental Scan ({base}..{head}):[/bold blue]")
            changed_files = parse_git_diff(base, head, target)
            categorized = categorize_findings(all_findings, all_findings, changed_files)
            new_findings = categorized["new"] + categorized["existing"]
            # Just keep everything in session.findings or narrow down? The requirement says return error codes strictly based on policy. Policy evaluates (all, new).
            
        # --- Determine Exit Code using Policy ---
        policy = None
        if policy_file:
            policy = Policy(policy_file)
        else:
            policy = Policy("default")
            severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            fail_val = fail_on.upper()
            if fail_val in severity_levels:
                idx = severity_levels.index(fail_val)
                policy.fail_on = severity_levels[idx:]
            else:
                policy.fail_on = ["HIGH", "CRITICAL"]

        passed = policy.evaluate(all_findings, new_findings)
        exit_code = 0 if passed else 1

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
                
            if passed:
                console.print(f"\n[bold green]Scan completed. Findings found, but none meet the failure threshold.[/bold green]")
            else:
                console.print(f"\n[bold red]Scan failed policy check.[/bold red]")
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

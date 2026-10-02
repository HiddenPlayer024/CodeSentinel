from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from codesentinel.models.core import ScanSession
from .base import BaseReporter

class HtmlReporter(BaseReporter):
    """Generates an HTML standalone report using Jinja2."""
    
    def generate(self, session: ScanSession, output_path: Path) -> None:
        templates_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(str(templates_dir)))
        template = env.get_template("report.html")
        
        # Calculate summary metrics
        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in session.findings:
            severities[f.severity.value] += 1
            
        html_content = template.render(
            session=session,
            project=session.project,
            findings=session.findings,
            severities=severities
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

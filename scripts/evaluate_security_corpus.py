import sys
import os
import json
import subprocess
import argparse
import time
# Benchmark reproducibility: Standard pseudo-random number generator is intentionally
# used here with a fixed seed for statistical bootstrapping and evaluation reproducibility.
# This is NOT used for cryptographic purposes, security decisions, or sensitive tokens.
import random # nosec
from pathlib import Path
from datetime import datetime

def bootstrap_ci(expected_vuln, expected_safe, found_files, n_iterations=1000, seed=42):
    random.seed(seed)
    precisions = []
    recalls = []
    
    all_files = expected_vuln + expected_safe
    labels = {f: "vulnerable" for f in expected_vuln}
    labels.update({f: "safe" for f in expected_safe})
    
    for _ in range(n_iterations):
        sample = random.choices(all_files, k=len(all_files))
        sample_tp = sum(1 for f in sample if labels[f] == "vulnerable" and f in found_files)
        sample_fp = sum(1 for f in sample if labels[f] == "safe" and f in found_files)
        sample_fn = sum(1 for f in sample if labels[f] == "vulnerable" and f not in found_files)
        
        p = sample_tp / (sample_tp + sample_fp) if (sample_tp + sample_fp) > 0 else 0.0
        r = sample_tp / (sample_tp + sample_fn) if (sample_tp + sample_fn) > 0 else 0.0
        precisions.append(p)
        recalls.append(r)
        
    precisions.sort()
    recalls.sort()
    p_lower = precisions[int(n_iterations * 0.025)]
    p_upper = precisions[int(n_iterations * 0.975)]
    r_lower = recalls[int(n_iterations * 0.025)]
    r_upper = recalls[int(n_iterations * 0.975)]
    
    return (p_lower, p_upper), (r_lower, r_upper)

def calculate_metrics(expected_vuln, expected_safe, found_files):
    tp = sum(1 for v in expected_vuln if v in found_files)
    fn = len(expected_vuln) - tp
    fp = sum(1 for s in expected_safe if s in found_files)
    tn = len(expected_safe) - fp
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return tp, fn, fp, tn, precision, recall, f1

def run_evaluation():
    parser = argparse.ArgumentParser(description="Evaluate security corpus")
    parser.add_argument("--provider", choices=["mock", "openai", "ollama"], default="mock", help="AI provider to use")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    corpus_dir = base_dir / "examples" / "security-corpus"
    eval_dir = base_dir / "evaluation"
    eval_dir.mkdir(exist_ok=True)
    
    manifest_file = eval_dir / "corpus_manifest.json"
    if not manifest_file.exists():
        print(f"Manifest not found at {manifest_file}. Please create it first.")
        return
        
    with open(manifest_file, "r") as f:
        manifest = json.load(f)
        
    fixtures = {item["file"]: item["label"] for item in manifest}
    
    if args.provider == "openai" and not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable is required when using the 'openai' provider.")
        sys.exit(1)
        
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = eval_dir / "runs" / run_timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
        
    results = {}
    
    modes = [
        {"name": "STATIC", "args": []},
        {"name": "AI_DISCOVERY", "args": ["--ai", "--ai-provider", args.provider, "--ai-mode", "discover", "--ai-max-files", "100", "--ai-max-review-units", "200"]},
        {"name": "HYBRID", "args": ["--ai", "--ai-provider", args.provider, "--ai-mode", "hybrid", "--ai-max-files", "100", "--ai-max-review-units", "200"]}
    ]
    
    openai_telemetry = {"latency": {}, "errors": {}, "timeouts": {}}
    
    for mode in modes:
        mode_name = mode["name"]
        print(f"Evaluating mode: {mode_name}")
        
        output_file = run_dir / f"{mode_name.lower()}.json"
        
        env = os.environ.copy()
        env["AI_MAX_FILES"] = "100"
        env["PYTHONPATH"] = str(base_dir)
        env["AI_MAX_REVIEW_UNITS"] = "200"
        env["MOCK_FIXTURES"] = json.dumps(fixtures)
        
        venv_python = str(base_dir / ".venv" / "bin" / "python")
        if not os.path.exists(venv_python):
            venv_python = sys.executable

        cmd = [
            venv_python, "-m", "codesentinel.cli.main",
            "scan",
            str(corpus_dir),
            "--format", "json",
            "--output", str(output_file)
        ] + mode["args"]
        
        start_time = time.time()
        process = subprocess.run(cmd, cwd=str(base_dir), env=env, capture_output=True, text=True)
        end_time = time.time()
        duration = end_time - start_time
        
        if process.returncode != 0 and process.returncode != 1:  # 1 is returned when findings fail threshold
            print(f"Error running mode {mode_name}:")
            print(process.stderr)
        
        if args.provider == "openai" and mode_name != "STATIC":
            openai_telemetry["latency"][mode_name] = duration
            stderr = process.stderr
            stdout = process.stdout
            out = stdout + stderr
            error_count = out.count("OpenAI API Error")
            timeout_count = out.count("ReadTimeout") + out.count("TimeoutError") + out.count("timeout")
            openai_telemetry["errors"][mode_name] = error_count
            openai_telemetry["timeouts"][mode_name] = timeout_count
        
        if output_file.exists():
            with open(output_file, "r") as f:
                scan_data = json.load(f)
        else:
            scan_data = {"findings": []}
            
        findings = scan_data.get("findings", [])
        
        expected_vulnerable = [item["file"] for item in manifest if item["label"] == "vulnerable"]
        expected_safe = [item["file"] for item in manifest if item["label"] == "safe"]
        
        found_files = set()
        finding_count = len(findings)
        
        for finding in findings:
            file_path = finding["location"]["file"]
            try:
                rel_path = str(Path(file_path).relative_to(corpus_dir))
                found_files.add(rel_path)
            except ValueError:
                found_files.add(file_path)
                
        tp, fn, fp, tn, precision, recall, f1 = calculate_metrics(expected_vulnerable, expected_safe, found_files)
        p_ci, r_ci = bootstrap_ci(expected_vulnerable, expected_safe, list(found_files))
        
        # Family level
        family_metrics = {}
        families = set(item.get("family", "unknown") for item in manifest)
        for family in families:
            fam_vuln = [item["file"] for item in manifest if item["label"] == "vulnerable" and item.get("family") == family]
            fam_safe = [item["file"] for item in manifest if item["label"] == "safe" and item.get("family") == family]
            f_tp, f_fn, f_fp, f_tn, f_precision, f_recall, f_f1 = calculate_metrics(fam_vuln, fam_safe, found_files)
            family_metrics[family] = {
                "tp": f_tp, "fn": f_fn, "fp": f_fp, "tn": f_tn,
                "precision": f_precision, "recall": f_recall, "f1": f_f1
            }
        
        results[mode_name] = {
            "case_metrics": {
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": precision, "recall": recall, "f1": f1,
                "precision_ci_95": p_ci, "recall_ci_95": r_ci
            },
            "finding_metrics": {
                "total_findings": finding_count,
            },
            "family_metrics": family_metrics,
            "found_files": list(found_files),
            "findings": findings,
            "duration": duration
        }
        
    static_tp = results.get("STATIC", {}).get("case_metrics", {}).get("tp", 0)
    static_fp = results.get("STATIC", {}).get("case_metrics", {}).get("fp", 0)
    hybrid_tp = results.get("HYBRID", {}).get("case_metrics", {}).get("tp", 0)
    hybrid_fp = results.get("HYBRID", {}).get("case_metrics", {}).get("fp", 0)
    static_recall = results.get("STATIC", {}).get("case_metrics", {}).get("recall", 0.0)
    hybrid_recall = results.get("HYBRID", {}).get("case_metrics", {}).get("recall", 0.0)
    
    ai_added_tp = hybrid_tp - static_tp
    ai_added_fp = hybrid_fp - static_fp
    hybrid_recall_diff = hybrid_recall - static_recall
    
    results["semantic_lift"] = {
        "ai_added_tp": ai_added_tp,
        "ai_added_fp": ai_added_fp,
        "hybrid_recall_diff": hybrid_recall_diff
    }
    
    if args.provider == "openai":
        results["openai_telemetry"] = openai_telemetry
        
    # Write metadata.json
    metadata = {
        "timestamp": run_timestamp,
        "provider": args.provider,
        "corpus_size": len(manifest),
        "families": len(families)
    }
    with open(run_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
        
    with open(run_dir / "results.json", "w") as f:
        json.dump(results, f, indent=2)
        
    summary_file = run_dir / "summary.md"
    with open(summary_file, "w") as f:
        f.write(f"# Security Corpus Evaluation Summary (Provider: {args.provider})\n\n")
        f.write("## Case-Level Metrics\n\n")
        f.write("| Mode | TP | FP | FN | TN | Precision | Recall | F1 Score | Precision 95% CI | Recall 95% CI | Total Findings |\n")
        f.write("|------|----|----|----|----|-----------|--------|----------|------------------|---------------|----------------|\n")
        for mode_name in ["STATIC", "AI_DISCOVERY", "HYBRID"]:
            data = results[mode_name]
            cm = data["case_metrics"]
            fm = data["finding_metrics"]
            p_ci = f"[{cm['precision_ci_95'][0]:.2f}, {cm['precision_ci_95'][1]:.2f}]"
            r_ci = f"[{cm['recall_ci_95'][0]:.2f}, {cm['recall_ci_95'][1]:.2f}]"
            f.write(f"| {mode_name} | {cm['tp']} | {cm['fp']} | {cm['fn']} | {cm['tn']} | {cm['precision']:.2f} | {cm['recall']:.2f} | {cm['f1']:.2f} | {p_ci} | {r_ci} | {fm['total_findings']} |\n")
            
        f.write("\n## Semantic Lift\n")
        f.write(f"- AI-Added TP: {ai_added_tp}\n")
        f.write(f"- AI-Added FP: {ai_added_fp}\n")
        f.write(f"- Hybrid Recall Improvement: {hybrid_recall_diff:.2%}\n")
        
        f.write("\n## Family-Level Metrics (Hybrid Mode)\n\n")
        f.write("| Family | TP | FP | FN | TN | Precision | Recall | F1 |\n")
        f.write("|--------|----|----|----|----|-----------|--------|----|\n")
        fam_metrics = results["HYBRID"]["family_metrics"]
        for fam, metrics in fam_metrics.items():
            f.write(f"| {fam} | {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | {metrics['tn']} | {metrics['precision']:.2f} | {metrics['recall']:.2f} | {metrics['f1']:.2f} |\n")
            
        if args.provider == "openai":
            f.write("\n## OpenAI Telemetry\n")
            f.write("```json\n")
            f.write(json.dumps(openai_telemetry, indent=2))
            f.write("\n```\n")
            
    matrix_file = eval_dir / "benchmark_matrix.md"
    with open(matrix_file, "w") as f:
        f.write("# Benchmark Matrix\n\n")
        f.write("| Case | Language | Family | Label | Static | AI | Hybrid | Expected source | Detected source | Relationship |\n")
        f.write("|------|----------|--------|-------|--------|----|--------|-----------------|-----------------|--------------|\n")
        
        hybrid_findings_by_file = {}
        if "HYBRID" in results and "findings" in results["HYBRID"]:
            for finding in results["HYBRID"]["findings"]:
                file_path = finding["location"]["file"]
                try:
                    rel_path = str(Path(file_path).relative_to(corpus_dir))
                except ValueError:
                    rel_path = file_path
                if rel_path not in hybrid_findings_by_file:
                    hybrid_findings_by_file[rel_path] = []
                hybrid_findings_by_file[rel_path].append(finding)
                
        for item in manifest:
            case_file = item["file"]
            lang = Path(case_file).suffix.strip('.')
            if not lang: lang = "unknown"
            family = item.get("family", "unknown")
            label = item.get("label", "unknown")
            
            static_found = "Yes" if case_file in results.get("STATIC", {}).get("found_files", []) else "No"
            ai_found = "Yes" if case_file in results.get("AI_DISCOVERY", {}).get("found_files", []) else "No"
            hybrid_found = "Yes" if case_file in results.get("HYBRID", {}).get("found_files", []) else "No"
            
            # Since test doesn't explicitly store Expected Source, we can infer: 
            # label indicates vulnerability, if it's "vulnerable" we expect finding, etc.
            # Usually Expected Source in similar context means "ai", "static" depending on test case intent? 
            # We'll just say "static/ai" or leave it as N/A. Let's do N/A for Expected.
            # Wait, the instruction says "Expected source". Is there expected source in manifest? Let's check manifest.
            expected_source = item.get("expected_source", "N/A")
            
            detected_sources = set()
            relationships = set()
            if hybrid_found == "Yes" and case_file in hybrid_findings_by_file:
                for finding in hybrid_findings_by_file[case_file]:
                    sources = finding.get("analysis_source", ["unknown"])
                    detected_sources.update(sources)
                    rel = finding.get("relationship", "standalone")
                    relationships.add(rel)
            
            det_src_str = ",".join(sorted(detected_sources)) if detected_sources else "None"
            rel_str = ",".join(sorted(relationships)) if relationships else "None"
            
            f.write(f"| {case_file} | {lang} | {family} | {label} | {static_found} | {ai_found} | {hybrid_found} | {expected_source} | {det_src_str} | {rel_str} |\n")

    print(f"Evaluation complete. Results stored in {run_dir}/summary.md and {matrix_file}")

if __name__ == "__main__":
    run_evaluation()

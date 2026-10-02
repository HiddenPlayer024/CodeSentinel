import sys
import os
import json
import subprocess
import argparse
from pathlib import Path

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
        
    results = {}
    
    modes = [
        {"name": "STATIC", "args": []},
        {"name": "AI_DISCOVERY", "args": ["--ai", "--ai-provider", args.provider, "--ai-mode", "discover", "--ai-max-files", "100", "--ai-max-review-units", "200"]},
        {"name": "HYBRID", "args": ["--ai", "--ai-provider", args.provider, "--ai-mode", "hybrid", "--ai-max-files", "100", "--ai-max-review-units", "200"]}
    ]
    
    for mode in modes:
        mode_name = mode["name"]
        print(f"Evaluating mode: {mode_name}")
        
        output_file = eval_dir / f"results_{mode_name.lower()}.json"
        
        env = os.environ.copy()
        env["AI_MAX_FILES"] = "100"
        env["PYTHONPATH"] = str(base_dir)
        env["AI_MAX_REVIEW_UNITS"] = "200"
        
        cmd = [
            sys.executable, "-m", "codesentinel.cli.main",
            "scan",
            str(corpus_dir),
            "--format", "json",
            "--output", str(output_file)
        ] + mode["args"]
        
        subprocess.run(cmd, cwd=str(base_dir), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
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
                
        tp = sum(1 for v in expected_vulnerable if v in found_files)
        fn = len(expected_vulnerable) - tp
        fp = sum(1 for s in expected_safe if s in found_files)
        tn = len(expected_safe) - fp
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        results[mode_name] = {
            "case_metrics": {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "precision": precision,
                "recall": recall,
                "f1": f1
            },
            "finding_metrics": {
                "total_findings": finding_count,
            },
            "found_files": list(found_files)
        }
        
    static_tp_files = set(expected_vulnerable).intersection(set(results.get("STATIC", {}).get("found_files", [])))
    hybrid_tp_files = set(expected_vulnerable).intersection(set(results.get("HYBRID", {}).get("found_files", [])))
    added_files = hybrid_tp_files - static_tp_files
    hybrid_added_recall = len(added_files) / len(expected_vulnerable) if expected_vulnerable else 0.0
    
    summary_file = eval_dir / "summary.md"
    with open(summary_file, "w") as f:
        f.write("# Security Corpus Evaluation Summary\n\n")
        f.write("## Case-Level Metrics\n\n")
        f.write("| Mode | TP | FP | FN | TN | Precision | Recall | F1 Score | Total Findings |\n")
        f.write("|------|----|----|----|----|-----------|--------|----------|----------------|\n")
        for mode_name, data in results.items():
            cm = data["case_metrics"]
            fm = data["finding_metrics"]
            f.write(f"| {mode_name} | {cm['tp']} | {cm['fp']} | {cm['fn']} | {cm['tn']} | {cm['precision']:.2f} | {cm['recall']:.2f} | {cm['f1']:.2f} | {fm['total_findings']} |\n")
            
        f.write(f"\n**Hybrid Added Recall**: {hybrid_added_recall:.2%} (Found {len(added_files)} additional vulnerable files over Static)\n")
            
    with open(eval_dir / "results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("Evaluation complete. Check evaluation/summary.md for details.")

if __name__ == "__main__":
    run_evaluation()

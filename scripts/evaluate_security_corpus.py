import os
import json
import subprocess
from pathlib import Path

def run_evaluation():
    base_dir = Path(os.path.abspath(__file__)).parent.parent
    corpus_dir = base_dir / "examples" / "security-corpus"
    eval_dir = base_dir / "evaluation"
    eval_dir.mkdir(exist_ok=True)
    
    results = {}
    
    # Modes to test
    modes = [
        {"name": "STATIC", "args": []},
        {"name": "AI_DISCOVERY", "args": ["--ai", "--ai-provider", "mock", "--ai-mode", "discover"]},
        {"name": "HYBRID", "args": ["--ai", "--ai-provider", "mock", "--ai-mode", "hybrid"]}
    ]
    
    for mode in modes:
        mode_name = mode["name"]
        print(f"Evaluating mode: {mode_name}")
        
        output_file = eval_dir / f"results_{mode_name.lower()}.json"
        
        cmd = [
            "python", "-m", "codesentinel.cli.main",
            "scan",
            str(corpus_dir),
            "--format", "json",
            "--output", str(output_file)
        ] + mode["args"]
        
        # Run the scan (ignore exit code as it will return 1 if findings)
        subprocess.run(cmd, cwd=str(base_dir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        with open(output_file, "r") as f:
            scan_data = json.load(f)
            
        findings = scan_data.get("findings", [])
        
        # Determine TP, FP, FN
        tp, fp, fn, tn = 0, 0, 0, 0
        
        # Expected files logic
        expected_vulnerable = []
        expected_safe = []
        
        for root, dirs, files in os.walk(corpus_dir):
            for file in files:
                file_path = Path(root) / file
                # Ignore non-code files
                if file_path.suffix not in [".py", ".js", ".json", ".yml", ".yaml"]:
                    continue
                
                rel_path = str(file_path.relative_to(corpus_dir))
                if "vulnerable/" in rel_path or "variant/" in rel_path:
                    expected_vulnerable.append(rel_path)
                elif "safe/" in rel_path or "false_positive/" in rel_path:
                    expected_safe.append(rel_path)
                    
        # Group findings by file
        found_files = set()
        for finding in findings:
            file_path = finding["location"]["file"]
            try:
                rel_path = str(Path(file_path).relative_to(corpus_dir))
                found_files.add(rel_path)
            except ValueError:
                found_files.add(file_path)
                
        # Calculate TP, FN
        for v in expected_vulnerable:
            if v in found_files:
                tp += 1
            else:
                fn += 1
                
        # Calculate FP, TN
        for s in expected_safe:
            if s in found_files:
                fp += 1
            else:
                tn += 1
                
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        results[mode_name] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": f1
        }
        
    # Write summary
    summary_file = eval_dir / "summary.md"
    with open(summary_file, "w") as f:
        f.write("# Security Corpus Evaluation Summary\n\n")
        f.write("| Mode | TP | FP | FN | TN | Precision | Recall | F1 Score |\n")
        f.write("|------|----|----|----|----|-----------|--------|----------|\n")
        for mode_name, metrics in results.items():
            f.write(f"| {mode_name} | {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | {metrics['tn']} | {metrics['precision']:.2f} | {metrics['recall']:.2f} | {metrics['f1']:.2f} |\n")
            
    with open(eval_dir / "results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("Evaluation complete. Check evaluation/summary.md for details.")

if __name__ == "__main__":
    run_evaluation()

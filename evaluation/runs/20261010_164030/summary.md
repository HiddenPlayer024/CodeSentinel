# Security Corpus Evaluation Summary (Provider: mock)

## Case-Level Metrics

| Mode | TP | FP | FN | TN | Precision | Recall | F1 Score | Precision 95% CI | Recall 95% CI | Total Findings |
|------|----|----|----|----|-----------|--------|----------|------------------|---------------|----------------|
| STATIC | 20 | 3 | 47 | 9 | 0.87 | 0.30 | 0.44 | [0.70, 1.00] | [0.19, 0.42] | 38 |
| AI_DISCOVERY | 52 | 0 | 15 | 12 | 1.00 | 0.78 | 0.87 | [1.00, 1.00] | [0.67, 0.88] | 52 |
| HYBRID | 58 | 3 | 9 | 9 | 0.95 | 0.87 | 0.91 | [0.89, 1.00] | [0.77, 0.94] | 90 |

## Semantic Lift
- AI-Added TP: 38
- AI-Added FP: 0
- Hybrid Recall Improvement: 56.72%

## Family-Level Metrics (Hybrid Mode)

| Family | TP | FP | FN | TN | Precision | Recall | F1 |
|--------|----|----|----|----|-----------|--------|----|
| complex | 1 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| auth_bypass | 0 | 0 | 1 | 0 | 0.00 | 0.00 | 0.00 |
| ssrf | 3 | 2 | 0 | 0 | 0.60 | 1.00 | 0.75 |
| obfuscated | 0 | 0 | 1 | 0 | 0.00 | 0.00 | 0.00 |
| ssti | 2 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| path_traversal | 0 | 0 | 1 | 1 | 0.00 | 0.00 | 0.00 |
| crypto | 1 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| xxe | 0 | 0 | 1 | 0 | 0.00 | 0.00 | 0.00 |
| unknown | 11 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| prompt_injection | 0 | 0 | 1 | 1 | 0.00 | 0.00 | 0.00 |
| xss | 1 | 0 | 1 | 1 | 1.00 | 0.50 | 0.67 |
| command_injection | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| gh_actions | 1 | 0 | 1 | 2 | 1.00 | 0.50 | 0.67 |
| dummy | 35 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sqli | 1 | 1 | 2 | 1 | 0.50 | 0.33 | 0.40 |

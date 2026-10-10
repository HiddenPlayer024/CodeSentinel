# Security Corpus Evaluation Summary (Provider: mock)

## Case-Level Metrics

| Mode | TP | FP | FN | TN | Precision | Recall | F1 Score | Precision 95% CI | Recall 95% CI | Total Findings |
|------|----|----|----|----|-----------|--------|----------|------------------|---------------|----------------|
| STATIC | 18 | 3 | 5 | 5 | 0.86 | 0.78 | 0.82 | [0.68, 1.00] | [0.59, 0.95] | 35 |
| AI_DISCOVERY | 23 | 0 | 0 | 8 | 1.00 | 1.00 | 1.00 | [1.00, 1.00] | [1.00, 1.00] | 27 |
| HYBRID | 0 | 0 | 23 | 8 | 0.00 | 0.00 | 0.00 | [0.00, 0.00] | [0.00, 0.00] | 0 |

## Semantic Lift
- AI-Added TP: -18
- AI-Added FP: -3
- Hybrid Recall Improvement: -78.26%

## Family-Level Metrics (Hybrid Mode)

| Family | TP | FP | FN | TN | Precision | Recall | F1 |
|--------|----|----|----|----|-----------|--------|----|
| ssti | 0 | 0 | 2 | 1 | 0.00 | 0.00 | 0.00 |
| gh_actions | 0 | 0 | 2 | 2 | 0.00 | 0.00 | 0.00 |
| sqli | 0 | 0 | 1 | 1 | 0.00 | 0.00 | 0.00 |
| xss | 0 | 0 | 1 | 0 | 0.00 | 0.00 | 0.00 |
| unknown | 0 | 0 | 11 | 0 | 0.00 | 0.00 | 0.00 |
| xxe | 0 | 0 | 1 | 0 | 0.00 | 0.00 | 0.00 |
| command_injection | 0 | 0 | 2 | 2 | 0.00 | 0.00 | 0.00 |
| ssrf | 0 | 0 | 3 | 2 | 0.00 | 0.00 | 0.00 |

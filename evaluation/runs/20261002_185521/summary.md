# Security Corpus Evaluation Summary (Provider: mock)

## Case-Level Metrics

| Mode | TP | FP | FN | TN | Precision | Recall | F1 Score | Precision 95% CI | Recall 95% CI | Total Findings |
|------|----|----|----|----|-----------|--------|----------|------------------|---------------|----------------|
| STATIC | 18 | 3 | 5 | 5 | 0.86 | 0.78 | 0.82 | [0.68, 1.00] | [0.59, 0.95] | 35 |
| AI_DISCOVERY | 23 | 0 | 0 | 8 | 1.00 | 1.00 | 1.00 | [1.00, 1.00] | [1.00, 1.00] | 27 |
| HYBRID | 23 | 3 | 0 | 5 | 0.88 | 1.00 | 0.94 | [0.73, 1.00] | [1.00, 1.00] | 58 |

## Semantic Lift
- AI-Added TP: 5
- AI-Added FP: 0
- Hybrid Recall Improvement: 21.74%

## Family-Level Metrics (Hybrid Mode)

| Family | TP | FP | FN | TN | Precision | Recall | F1 |
|--------|----|----|----|----|-----------|--------|----|
| xxe | 1 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| ssrf | 3 | 2 | 0 | 0 | 0.60 | 1.00 | 0.75 |
| gh_actions | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| unknown | 11 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sqli | 1 | 1 | 0 | 0 | 0.50 | 1.00 | 0.67 |
| ssti | 2 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| xss | 1 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| command_injection | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |

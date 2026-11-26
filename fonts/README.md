# Pentesa Bundled Typography & Font Assets

This directory bundles open-source, metric-compatible TrueType fonts for high-fidelity PDF report generation via ReportLab:

## 1. Bundled Fonts & Metrics Substitutions

| Requested Family | Bundled Open-Source Font | Target Files | Metric Compatibility | License |
|---|---|---|---|---|
| **Calibri** / Calibri-Bold | **Carlito** (Regular / Bold) | `fonts/carlito/Carlito-Regular.ttf`<br>`fonts/carlito/Carlito-Bold.ttf` | 100% metric-compatible with Microsoft Calibri | SIL Open Font License 1.1 (`fonts/carlito/LICENSE.txt`) |
| **Arial** / Arial-Bold | **Liberation Sans** (Regular / Bold) | `fonts/liberation/LiberationSans-Regular.ttf`<br>`fonts/liberation/LiberationSans-Bold.ttf` | 100% metric-compatible with Monotype Arial | SIL Open Font License 1.1 (`fonts/liberation/LICENSE.txt`) |

## 2. ReportLab Registration & Embedding
Fonts are registered at runtime using:
```python
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

pdfmetrics.registerFont(TTFont("Carlito", "fonts/carlito/Carlito-Regular.ttf"))
pdfmetrics.registerFont(TTFont("Carlito-Bold", "fonts/carlito/Carlito-Bold.ttf"))
pdfmetrics.registerFont(TTFont("LiberationSans", "fonts/liberation/LiberationSans-Regular.ttf"))
pdfmetrics.registerFont(TTFont("LiberationSans-Bold", "fonts/liberation/LiberationSans-Bold.ttf"))
```
When registered, TrueType font subsets are embedded directly in the output PDF document, guaranteeing identical cross-platform layout fidelity on Linux, Windows, macOS, and mobile viewers without reliance on host operating system fonts.

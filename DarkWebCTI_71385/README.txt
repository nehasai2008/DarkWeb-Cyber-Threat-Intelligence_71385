DarkWebCTI Standalone - Version 2.2

Open this folder in Apache NetBeans as a Maven project (pom.xml is in this folder).
Use Java 17 or newer. Run the project from NetBeans.

Workflow:
1. Select CSV Dataset.
2. Click Analyse Data.
3. Review the Dataset Analysis Report and Dashboard.

CSV guidance:
- Include a header row.
- Recommended columns: id, title/text/content/description, category, created_at/date.
- CSV fields containing commas or line breaks should be quoted.
- The application detects common comma, semicolon and tab delimiters.

Category-count correction:
- Category Counts and Unique non-empty categories use only valid values from the source category column.
- Missing or invalid source category values are counted as missing, not replaced by inferred text labels.
- Threat-type inference is separate and does not change the original category statistics.
- Malformed rows with a different number of columns are skipped to avoid shifting values into incorrect columns.

Limitations:
- Risk scores are heuristic keyword-based indicators, not verified threat assessments.
- IOC extraction identifies syntactic patterns only. Validate indicators with trusted sources.
- The application does not crawl the dark web or verify live threats.

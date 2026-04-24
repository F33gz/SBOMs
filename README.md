# SBOM Generation & Vulnerability Analysis

Automated pipeline for generating **Software Bill of Materials (SBOMs)** and performing **multi-dimensional security analysis** across a GitHub organization's top repositories.

Built with [Syft](https://github.com/anchore/syft) (SBOM generation), [Grype](https://github.com/anchore/grype) (vulnerability scanning), [Semgrep](https://semgrep.dev/) (SAST), and [Jupyter Lab](https://jupyter.org/) (interactive analysis).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    docker-compose.yml                        │
│                                                             │
│  ┌─────────────────────┐        ┌────────────────────────┐  │
│  │   🔧 processor      │        │   📊 jupyter           │  │
│  │                     │        │                        │  │
│  │  Python 3.12-slim   │        │  scipy-notebook        │  │
│  │  + Syft + Grype     │        │  + pandas + matplotlib │  │
│  │  + Semgrep          │        │  + seaborn             │  │
│  │                     │        │                        │  │
│  │  1. GitHub API      │        │  Reads JSON files      │  │
│  │  2. Top 5 repos     │        │  from /data and runs   │  │
│  │  3. Generate SBOMs  │  ───►  │  interactive analysis  │  │
│  │  4. Scan vulns      │ /data  │                        │  │
│  │  5. Analyze CI/CD   │        │  Port: 8888            │  │
│  │  6. Run SAST        │        │                        │  │
│  │  7. Exit            │        │                        │  │
│  └─────────────────────┘        └────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- **Docker** (v20.10+) and **Docker Compose** (v2.0+)
- A **GitHub Personal Access Token** (PAT) with the appropriate scopes:
  - **Public repos only**: No scopes needed (classic token)
  - **Private repos**: `repo` scope required
  - Generate one at: [github.com/settings/tokens](https://github.com/settings/tokens)

---

## Quick Start

### 1. Clone this repository

```bash
git clone https://github.com/F33gz/SBOMs.git
cd SBOMs
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your values:

```env
GITHUB_ORG=your-org-name
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 3. Build and run

```bash
docker-compose up --build
```

This will:
1. **Build** the processor image (installs Python, Syft, Grype, and Semgrep).
2. **Run** the processor — it selects the **top 5 most popular** repos by stars, generates SBOMs, scans vulnerabilities, analyzes CI/CD workflows, and runs SAST.
3. **Start** Jupyter Lab once the processor finishes.

### 4. Access Jupyter Lab

Open your browser and navigate to:

```
http://localhost:8888/lab?token=sbom-analysis
```

Then open the `work/analysis.ipynb` notebook and run all cells.

---

## Project Structure

```
SBOMs/
├── docker-compose.yml          # Orchestrates both services
├── .env.example                # Environment variables template
├── .gitignore                  # Excludes .env, data/, etc.
├── README.md                   # This file
├── tarea.md                    # Assignment description
├── processor/
│   ├── Dockerfile              # Python + Syft + Grype + Semgrep image
│   ├── requirements.txt        # Python dependencies
│   └── main.py                 # Repo scanning & analysis pipeline
└── notebooks/
    └── analysis.ipynb          # Jupyter Notebook with visualizations
```

**Generated at runtime** (in the Docker volume, not committed):

```
/data/
├── sbom_<repo-name>.json       # SBOM for each repository (Syft)
├── vuln_<repo-name>.json       # Vulnerability report for each repo (Grype)
├── sast_<repo-name>.json       # SAST report for each repo (Semgrep)
├── workflows_<repo-name>.json  # CI/CD workflow analysis for each repo
├── manifest.json               # Processing metadata & summary
├── chart_severity_distribution.png
├── chart_top3_repos.png
├── chart_top5_packages.png
├── chart_heatmap.png
├── chart_workflow_risks.png
├── chart_sast_findings.png
├── summary_table.csv
└── all_vulnerabilities.csv     # Full dataset export
```

---

## Analysis Features

The Jupyter Notebook provides the following analyses across three dimensions:

### Dimension 1: Dependencies (Quantitative)
| # | Analysis | Visualization |
|---|---|---|
| 1 | Vulnerability distribution by severity | Pie chart |
| 2 | Top 3 most insecure repositories | Horizontal stacked bar chart |
| 3 | Top 5 guilty dependencies | Styled table + grouped bar chart |
| 4 | Repos × Severity heatmap | Heatmap |

### Dimension 2: CI/CD Configurations
| # | Analysis | Visualization |
|---|---|---|
| 5 | Workflow risk analysis | Tables + bar charts |

### Dimension 3: Code Source (SAST)
| # | Analysis | Visualization |
|---|---|---|
| 6 | Semgrep static analysis findings | Tables + bar charts |

### Qualitative Analysis
| # | Section |
|---|---|
| 7.1 | Justification of organization selection |
| 7.2 | Interpretation of quantitative results |
| 7.3 | Relation to known security incidents |
| 7.4 | Local vs. systemic problem discussion |
| 8 | Comparative summary table |

---

## Configuration

| Variable | Description | Default |
|---|---|---|
| `GITHUB_ORG` | GitHub organization to scan | (required) |
| `GITHUB_TOKEN` | GitHub PAT for API access | (required for private repos) |
| `JUPYTER_TOKEN` | Token to access Jupyter Lab | `sbom-analysis` |

The processor has the following built-in defaults (can be modified in `main.py`):

| Setting | Value |
|---|---|
| Max repositories | 5 (top by stars) |
| Clone depth | 1 (shallow) |
| Clone timeout | 300s |
| Syft/Grype timeout | 600s |
| Semgrep timeout | 600s |

---

## Troubleshooting

### Processor exits with "GitHub API error"
- Verify `GITHUB_ORG` is spelled correctly.
- Ensure `GITHUB_TOKEN` has the required scopes.
- Check if your token has expired.

### Jupyter shows "No vulnerability files found"
- The processor may still be running. Wait for it to complete.
- Check processor logs: `docker-compose logs processor`

### Port 8888 is already in use
Change the port mapping in `docker-compose.yml`:
```yaml
ports:
  - "9999:8888"  # Change 9999 to any free port
```

### Want to re-run the processor?
```bash
docker-compose down
docker volume rm sboms_sbom-data
docker-compose up --build
```

### View processor logs only
```bash
docker-compose logs -f processor
```

---

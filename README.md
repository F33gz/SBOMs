# SBOM Generation & Vulnerability Analysis

Automated pipeline for generating **Software Bill of Materials (SBOMs)** and performing **vulnerability analysis** across a GitHub organization's repositories.

Built with [Syft](https://github.com/anchore/syft) (SBOM generation), [Grype](https://github.com/anchore/grype) (vulnerability scanning), and [Jupyter Lab](https://jupyter.org/) (interactive analysis).

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
│  │                     │        │  + seaborn             │  │
│  │  1. GitHub API      │        │                        │  │
│  │  2. Clone repos     │        │  Reads JSON files      │  │
│  │  3. Generate SBOMs  │  ───►  │  from /data and runs   │  │
│  │  4. Scan vulns      │ /data  │  interactive analysis  │  │
│  │  5. Exit            │        │                        │  │
│  └─────────────────────┘        │  Port: 8888            │  │
│                                 └────────────────────────┘  │
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
git clone https://github.com/your-user/SBOMs.git
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
1. **Build** the processor image (installs Python, Syft, and Grype).
2. **Run** the processor — it scans your organization's repos (those active in the last 30 days, max 50).
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
├── processor/
│   ├── Dockerfile              # Python + Syft + Grype image
│   ├── requirements.txt        # Python dependencies
│   └── main.py                 # Repo scanning & SBOM pipeline
└── notebooks/
    └── analysis.ipynb          # Jupyter Notebook with visualizations
```

**Generated at runtime** (in the Docker volume, not committed):

```
/data/
├── sbom_<repo-name>.json       # SBOM for each repository (Syft)
├── vuln_<repo-name>.json       # Vulnerability report for each repo (Grype)
├── manifest.json               # Processing metadata & summary
├── chart_severity_distribution.png
├── chart_top3_repos.png
├── chart_top5_packages.png
└── all_vulnerabilities.csv     # Full dataset export
```

---

## Analysis Features

The Jupyter Notebook provides three key analyses:

| # | Analysis | Visualization |
|---|---|---|
| 1 | Vulnerability distribution by severity | Pie chart |
| 2 | Top 3 most insecure repositories |  Horizontal stacked bar chart |
| 3 | Top 5 guilty dependencies | Styled DataFrame + grouped bar chart |

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
| Max repositories | 50 |
| Activity window | Last 30 days |
| Clone depth | 1 (shallow) |
| Clone timeout | 300s |
| Syft/Grype timeout | 600s |

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

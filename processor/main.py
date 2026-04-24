#!/usr/bin/env python3
"""
SBOM Processor - GitHub Organization Scanner

Clones the top 5 most popular repositories from a GitHub organization,
generates SBOMs using Syft, runs vulnerability analysis using Grype,
analyzes CI/CD workflow configurations, and performs SAST with Semgrep.
Output JSON files are saved to /data for analysis in Jupyter Lab.
"""

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

GITHUB_ORG = os.environ.get("GITHUB_ORG", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
DATA_DIR = "/data"
MAX_REPOS = 5
GITHUB_API_BASE = "https://api.github.com"


def log_info(msg: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] INFO  {msg}")


def log_success(msg: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] OK    {msg}")


def log_error(msg: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] ERROR {msg}", file=sys.stderr)


def log_warning(msg: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] WARN  {msg}")


def get_github_headers() -> dict:
    """Build HTTP headers for GitHub API requests."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def fetch_org_repos() -> list[dict]:
    """Fetch all repositories for the organization. Handles pagination."""
    all_repos = []
    page = 1
    max_pages = 10
    headers = get_github_headers()

    log_info(f"Fetching repositories for organization: {GITHUB_ORG}")

    while page <= max_pages:
        url = f"{GITHUB_API_BASE}/orgs/{GITHUB_ORG}/repos"
        params = {
            "per_page": 100,
            "page": page,
            "type": "all",
            "sort": "pushed",
            "direction": "desc",
        }

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        repos = response.json()
        if not repos:
            break

        all_repos.extend(repos)
        page += 1

    log_info(f"Total repositories found: {len(all_repos)}")
    return all_repos


def select_top_repos(repos: list[dict]) -> list[dict]:
    """Select the top MAX_REPOS repositories by star count (popularity)."""
    # Sort by stars descending
    sorted_repos = sorted(
        repos,
        key=lambda r: r.get("stargazers_count", 0),
        reverse=True,
    )

    top = sorted_repos[:MAX_REPOS]

    log_info(f"Selected top {len(top)} repositories by popularity (stars):")
    for i, repo in enumerate(top, 1):
        stars = repo.get("stargazers_count", 0)
        name = repo.get("name", "unknown")
        log_info(f"  {i}. {name} ({stars:,} stars)")

    return top


def clone_repo(repo: dict, target_dir: str) -> bool:
    """Shallow-clone a repository. Injects token for private repo access."""
    clone_url = repo.get("clone_url", "")

    if GITHUB_TOKEN and clone_url.startswith("https://"):
        clone_url = clone_url.replace(
            "https://", f"https://x-access-token:{GITHUB_TOKEN}@"
        )

    repo_name = repo.get("name", "unknown")
    log_info(f"Cloning {repo_name} (shallow)...")

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", clone_url, target_dir],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return True
    except subprocess.CalledProcessError as e:
        log_error(f"Failed to clone {repo_name}: {e.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        log_error(f"Clone of {repo_name} timed out after 300s")
        return False


def run_syft(repo_name: str, repo_dir: str) -> str | None:
    """Run Syft to generate an SBOM. Returns the output path or None on failure."""
    sbom_path = os.path.join(DATA_DIR, f"sbom_{repo_name}.json")
    log_info(f"Running Syft on {repo_name}...")

    try:
        subprocess.run(
            [
                "syft",
                f"dir:{repo_dir}",
                "--output", f"syft-json={sbom_path}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        log_success(f"SBOM generated: sbom_{repo_name}.json")
        return sbom_path
    except subprocess.CalledProcessError as e:
        log_error(f"Syft failed for {repo_name}: {e.stderr.strip()}")
        return None
    except subprocess.TimeoutExpired:
        log_error(f"Syft timed out for {repo_name} after 600s")
        return None


def run_grype(repo_name: str, sbom_path: str) -> str | None:
    """Run Grype on the SBOM to generate a vulnerability report. Returns path or None."""
    vuln_path = os.path.join(DATA_DIR, f"vuln_{repo_name}.json")
    log_info(f"Running Grype on {repo_name}...")

    try:
        subprocess.run(
            [
                "grype",
                f"sbom:{sbom_path}",
                "--output", "json",
                "--file", vuln_path,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        log_success(f"Vulnerability report generated: vuln_{repo_name}.json")
        return vuln_path
    except subprocess.CalledProcessError as e:
        # Grype exits with code 1 when vulnerabilities are found, which is expected
        if os.path.exists(vuln_path) and os.path.getsize(vuln_path) > 0:
            log_success(f"Vulnerability report generated (with findings): vuln_{repo_name}.json")
            return vuln_path
        log_error(f"Grype failed for {repo_name}: {e.stderr.strip()}")
        return None
    except subprocess.TimeoutExpired:
        log_error(f"Grype timed out for {repo_name} after 600s")
        return None


def run_semgrep(repo_name: str, repo_dir: str) -> str | None:
    """Run Semgrep for static analysis (SAST). Returns output path or None."""
    sast_path = os.path.join(DATA_DIR, f"sast_{repo_name}.json")
    log_info(f"Running Semgrep on {repo_name}...")

    try:
        subprocess.run(
            [
                "semgrep", "scan",
                "--config", "auto",
                "--json",
                "--output", sast_path,
                "--quiet",
                repo_dir,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        log_success(f"SAST report generated: sast_{repo_name}.json")
        return sast_path
    except subprocess.CalledProcessError as e:
        # Semgrep exits with code 1 when findings are present
        if os.path.exists(sast_path) and os.path.getsize(sast_path) > 0:
            log_success(f"SAST report generated (with findings): sast_{repo_name}.json")
            return sast_path
        log_error(f"Semgrep failed for {repo_name}: {e.stderr.strip()[:300]}")
        return None
    except subprocess.TimeoutExpired:
        log_error(f"Semgrep timed out for {repo_name} after 600s")
        return None


def analyze_workflows(repo_name: str, repo_dir: str) -> str | None:
    """Analyze GitHub Actions workflow files for risky configurations.
    
    Checks for:
    - pull_request_target trigger (dangerous)
    - Excessive permissions (write-all, contents: write, etc.)
    - Actions not pinned to SHA (uses: action@v1 vs action@sha256)
    - Script injection via github.event context in run blocks
    - Use of third-party actions without verification
    """
    workflows_dir = os.path.join(repo_dir, ".github", "workflows")
    results_path = os.path.join(DATA_DIR, f"workflows_{repo_name}.json")

    if not os.path.isdir(workflows_dir):
        log_info(f"No .github/workflows directory found for {repo_name}")
        # Save empty result
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump({"repository": repo_name, "workflows_found": 0, "findings": []}, f, indent=2)
        return results_path

    workflow_files = glob.glob(os.path.join(workflows_dir, "*.yml")) + \
                     glob.glob(os.path.join(workflows_dir, "*.yaml"))

    log_info(f"Analyzing {len(workflow_files)} workflow file(s) for {repo_name}...")

    findings = []

    for wf_path in workflow_files:
        wf_name = os.path.basename(wf_path)
        try:
            with open(wf_path, "r", encoding="utf-8") as f:
                content = f.read()
                wf_data = yaml.safe_load(content)
        except Exception as e:
            log_warning(f"Failed to parse workflow {wf_name}: {e}")
            continue

        if not isinstance(wf_data, dict):
            continue

        # Check 1: pull_request_target trigger
        triggers = wf_data.get("on", wf_data.get(True, {}))
        if isinstance(triggers, dict) and "pull_request_target" in triggers:
            findings.append({
                "file": wf_name,
                "risk_type": "dangerous_trigger",
                "severity": "High",
                "description": "Uses pull_request_target trigger which can expose secrets to untrusted PRs",
                "reference": "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
            })
        elif isinstance(triggers, list) and "pull_request_target" in triggers:
            findings.append({
                "file": wf_name,
                "risk_type": "dangerous_trigger",
                "severity": "High",
                "description": "Uses pull_request_target trigger which can expose secrets to untrusted PRs",
                "reference": "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
            })

        # Check 2: Excessive permissions
        permissions = wf_data.get("permissions", {})
        if isinstance(permissions, str) and permissions == "write-all":
            findings.append({
                "file": wf_name,
                "risk_type": "excessive_permissions",
                "severity": "High",
                "description": "Workflow uses write-all permissions, violating principle of least privilege",
            })
        elif isinstance(permissions, dict):
            for perm_key, perm_val in permissions.items():
                if perm_val == "write" and perm_key in ("contents", "packages", "actions"):
                    findings.append({
                        "file": wf_name,
                        "risk_type": "broad_write_permission",
                        "severity": "Medium",
                        "description": f"Workflow grants write permission on '{perm_key}'",
                    })

        # Check 3 & 4: Analyze jobs
        jobs = wf_data.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue

                # Job-level permissions
                job_perms = job_data.get("permissions", {})
                if isinstance(job_perms, str) and job_perms == "write-all":
                    findings.append({
                        "file": wf_name,
                        "risk_type": "excessive_permissions",
                        "severity": "High",
                        "description": f"Job '{job_name}' uses write-all permissions",
                    })

                steps = job_data.get("steps", [])
                if not isinstance(steps, list):
                    continue

                for step_idx, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue

                    # Check 3: Actions not pinned to SHA
                    uses = step.get("uses", "")
                    if uses and "@" in uses:
                        ref = uses.split("@")[1]
                        # Pinned to SHA if ref is 40 hex chars
                        if not re.match(r"^[a-f0-9]{40}$", ref):
                            # Check if it's a version tag (common but less secure)
                            action_name = uses.split("@")[0]
                            # Skip official actions/ as they're generally trusted
                            if not action_name.startswith("actions/"):
                                findings.append({
                                    "file": wf_name,
                                    "risk_type": "unpinned_action",
                                    "severity": "Medium",
                                    "description": f"Step {step_idx + 1} uses '{uses}' without SHA pinning (supply chain risk)",
                                })

                    # Check 4: Script injection via github.event context
                    run_cmd = step.get("run", "")
                    if run_cmd and "${{" in run_cmd:
                        # Look for potentially dangerous context references
                        dangerous_contexts = [
                            "github.event.issue.title",
                            "github.event.issue.body",
                            "github.event.pull_request.title",
                            "github.event.pull_request.body",
                            "github.event.comment.body",
                            "github.event.review.body",
                            "github.event.head_commit.message",
                            "github.event.commits",
                            "github.head_ref",
                        ]
                        for ctx in dangerous_contexts:
                            if ctx in run_cmd:
                                findings.append({
                                    "file": wf_name,
                                    "risk_type": "script_injection",
                                    "severity": "Critical",
                                    "description": f"Step {step_idx + 1} uses '{ctx}' in run command — potential command injection",
                                    "reference": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
                                })

    result = {
        "repository": repo_name,
        "workflows_found": len(workflow_files),
        "total_findings": len(findings),
        "findings": findings,
    }

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    if findings:
        log_success(f"Workflow analysis complete: {len(findings)} finding(s) in {repo_name}")
    else:
        log_success(f"Workflow analysis complete: no issues found in {repo_name}")

    return results_path


def process_repo(repo: dict) -> dict:
    """Full pipeline for one repo: clone, syft, grype, semgrep, workflow analysis, cleanup."""
    repo_name = repo.get("name", "unknown")
    result = {
        "name": repo_name,
        "full_name": repo.get("full_name", ""),
        "pushed_at": repo.get("pushed_at", ""),
        "language": repo.get("language", ""),
        "stars": repo.get("stargazers_count", 0),
        "forks": repo.get("forks_count", 0),
        "sbom_generated": False,
        "vuln_report_generated": False,
        "sast_generated": False,
        "workflow_analysis_generated": False,
        "error": None,
    }

    tmp_dir = tempfile.mkdtemp(prefix=f"sbom_{repo_name}_")

    try:
        if not clone_repo(repo, tmp_dir):
            result["error"] = "Clone failed"
            return result

        # 1. SBOM Generation (Syft)
        sbom_path = run_syft(repo_name, tmp_dir)
        if not sbom_path:
            result["error"] = "Syft failed"
            return result
        result["sbom_generated"] = True

        # 2. Vulnerability Scanning (Grype)
        vuln_path = run_grype(repo_name, sbom_path)
        if vuln_path:
            result["vuln_report_generated"] = True
        else:
            result["error"] = "Grype failed"

        # 3. CI/CD Workflow Analysis
        wf_path = analyze_workflows(repo_name, tmp_dir)
        if wf_path:
            result["workflow_analysis_generated"] = True

        # 4. Static Analysis (Semgrep)
        sast_path = run_semgrep(repo_name, tmp_dir)
        if sast_path:
            result["sast_generated"] = True
        else:
            log_warning(f"Semgrep analysis skipped or failed for {repo_name}")

    except Exception as e:
        result["error"] = str(e)
        log_error(f"Unexpected error processing {repo_name}: {e}")

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


def generate_manifest(results: list[dict], start_time: datetime) -> None:
    """Write manifest.json with metadata about the processing run."""
    end_time = datetime.now(timezone.utc)
    manifest = {
        "organization": GITHUB_ORG,
        "generated_at": end_time.isoformat(),
        "processing_duration_seconds": (end_time - start_time).total_seconds(),
        "total_repos_processed": len(results),
        "successful_sboms": sum(1 for r in results if r["sbom_generated"]),
        "successful_vuln_reports": sum(1 for r in results if r["vuln_report_generated"]),
        "successful_sast_reports": sum(1 for r in results if r["sast_generated"]),
        "successful_workflow_analyses": sum(1 for r in results if r["workflow_analysis_generated"]),
        "errors": sum(1 for r in results if r["error"]),
        "repositories": results,
    }

    manifest_path = os.path.join(DATA_DIR, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    log_success(f"Manifest saved to {manifest_path}")


def main() -> None:
    print("=" * 60)
    print("  SBOM Processor - GitHub Organization Scanner")
    print("=" * 60)
    print()

    if not GITHUB_ORG:
        log_error("GITHUB_ORG environment variable is not set.")
        sys.exit(1)

    if not GITHUB_TOKEN:
        log_warning("GITHUB_TOKEN is not set. Only public repositories will be accessible.")

    os.makedirs(DATA_DIR, exist_ok=True)
    start_time = datetime.now(timezone.utc)

    try:
        all_repos = fetch_org_repos()
    except requests.exceptions.HTTPError as e:
        log_error(f"GitHub API error: {e}")
        log_error("Check that GITHUB_ORG is correct and GITHUB_TOKEN has the required scopes.")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        log_error(f"Network error: {e}")
        sys.exit(1)

    repos = select_top_repos(all_repos)

    if not repos:
        log_warning("No repositories found. Exiting.")
        generate_manifest([], start_time)
        sys.exit(0)

    results = []
    for idx, repo in enumerate(repos, start=1):
        repo_name = repo.get("name", "unknown")
        print()
        print(f"{'─' * 60}")
        print(f"  [{idx}/{len(repos)}] Processing: {repo_name}")
        print(f"{'─' * 60}")

        result = process_repo(repo)
        results.append(result)

        if result["error"]:
            log_error(f"Repository {repo_name} completed with error: {result['error']}")
        else:
            log_success(f"Repository {repo_name} processed successfully.")

    print()
    print("=" * 60)
    print("  Processing Complete")
    print("=" * 60)
    generate_manifest(results, start_time)

    total = len(results)
    sboms = sum(1 for r in results if r["sbom_generated"])
    vulns = sum(1 for r in results if r["vuln_report_generated"])
    sast = sum(1 for r in results if r["sast_generated"])
    workflows = sum(1 for r in results if r["workflow_analysis_generated"])
    errors = sum(1 for r in results if r["error"])

    print(f"  Total repositories processed:   {total}")
    print(f"  SBOMs generated:                {sboms}")
    print(f"  Vulnerability reports generated: {vulns}")
    print(f"  SAST reports generated:          {sast}")
    print(f"  Workflow analyses generated:     {workflows}")
    print(f"  Errors:                          {errors}")
    print()

    if errors > 0:
        print("  Repositories with errors:")
        for r in results:
            if r["error"]:
                print(f"    - {r['name']}: {r['error']}")
        print()

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    log_success(f"All done in {duration:.1f} seconds. Output saved to {DATA_DIR}/")


if __name__ == "__main__":
    main()

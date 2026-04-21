#!/usr/bin/env python3
"""
SBOM Processor - GitHub Organization Scanner

Clones recently active repositories from a GitHub organization,
generates SBOMs using Syft, and runs vulnerability analysis using Grype.
Output JSON files are saved to /data for analysis in Jupyter Lab.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import requests

GITHUB_ORG = os.environ.get("GITHUB_ORG", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
DATA_DIR = "/data"
MAX_REPOS = 50
ACTIVITY_DAYS = 30
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


def filter_recent_repos(repos: list[dict]) -> list[dict]:
    """Keep only repos pushed within the last ACTIVITY_DAYS. Returns at most MAX_REPOS."""
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=ACTIVITY_DAYS)
    recent = []

    for repo in repos:
        pushed_at_str = repo.get("pushed_at", "")
        if not pushed_at_str:
            continue

        pushed_at = datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
        if pushed_at >= cutoff_date:
            recent.append(repo)

    recent.sort(key=lambda r: r.get("pushed_at", ""), reverse=True)
    filtered = recent[:MAX_REPOS]

    log_info(
        f"Repos with activity in the last {ACTIVITY_DAYS} days: "
        f"{len(recent)} (processing top {len(filtered)})"
    )
    return filtered


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


def process_repo(repo: dict) -> dict:
    """Full pipeline for one repo: clone, syft, grype, cleanup."""
    repo_name = repo.get("name", "unknown")
    result = {
        "name": repo_name,
        "full_name": repo.get("full_name", ""),
        "pushed_at": repo.get("pushed_at", ""),
        "language": repo.get("language", ""),
        "sbom_generated": False,
        "vuln_report_generated": False,
        "error": None,
    }

    tmp_dir = tempfile.mkdtemp(prefix=f"sbom_{repo_name}_")

    try:
        if not clone_repo(repo, tmp_dir):
            result["error"] = "Clone failed"
            return result

        sbom_path = run_syft(repo_name, tmp_dir)
        if not sbom_path:
            result["error"] = "Syft failed"
            return result
        result["sbom_generated"] = True

        vuln_path = run_grype(repo_name, sbom_path)
        if vuln_path:
            result["vuln_report_generated"] = True
        else:
            result["error"] = "Grype failed"

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

    repos = filter_recent_repos(all_repos)

    if not repos:
        log_warning("No repositories found with recent activity. Exiting.")
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
    errors = sum(1 for r in results if r["error"])

    print(f"  Total repositories processed:   {total}")
    print(f"  SBOMs generated:                {sboms}")
    print(f"  Vulnerability reports generated: {vulns}")
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

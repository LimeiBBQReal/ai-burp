"""云端采集 workflow 本地触发器.

用法:

    # 1. 准备 GitHub PAT (有 repo 权限), 放到环境变量:
    #    setx GITHUB_TOKEN ghp_xxxxxxxxxxxx
    #
    # 2. 触发单个 workflow:
    #    python -m aiburp.recon_trigger --task subdomain --target example.com
    #
    # 3. 触发全套:
    #    python -m aiburp.recon_trigger --target example.com --all
    #
    # 4. 触发 + 自动等结果 + 自动解密:
    #    python -m aiburp.recon_trigger --target example.com --all --wait --decode

机制:
    1. 通过 GitHub REST API (POST /repos/{owner}/{repo}/actions/workflows/{file}/dispatches)
       触发 workflow_dispatch
    2. 可选 --wait 轮询 run 状态直到完成
    3. 可选 --decode 调用 recon_decoder 解密结果
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any

import requests


DEFAULT_REPO = "LimeiBBQReal/ai-burp-recon"

WORKFLOWS = {
    "subdomain": "recon-subdomain.yml",
    "dns":       "recon-dns.yml",
    "ports":     "recon-portscan.yml",
    "banners":   "recon-banner.yml",
    "js":        "recon-js.yml",
    "dirs":      "recon-dir.yml",
    "params":    "recon-params.yml",
}


def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def trigger_workflow(repo: str, workflow_file: str, target: str, token: str) -> int:
    url = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_file}/dispatches"
    payload = {"ref": "main", "inputs": {"target": target}}
    r = requests.post(url, headers=_gh_headers(token), json=payload, timeout=15)
    if r.status_code == 204:
        print(f"  [OK] {workflow_file} 已触发")
        return 0
    print(f"  [ERR] {workflow_file} → HTTP {r.status_code}: {r.text[:200]}", file=sys.stderr)
    return 1


def wait_runs(repo: str, token: str, timeout_sec: int = 600) -> list[dict]:
    """轮询最近 10 分钟内由本 token 触发的 runs, 返回所有已完成列表."""
    url = f"https://api.github.com/repos/{repo}/actions/runs?per_page=20"
    deadline = time.time() + timeout_sec
    last_seen: dict[int, str] = {}
    finished: list[dict] = []

    while time.time() < deadline:
        try:
            r = requests.get(url, headers=_gh_headers(token), timeout=15)
            if r.status_code == 200:
                runs = r.json().get("workflow_runs", [])
                for run in runs:
                    if time.time() - time.mktime(time.strptime(run["created_at"], "%Y-%m-%dT%H:%M:%SZ")) > 600:
                        continue
                    rid = run["id"]
                    status = run["status"]
                    conclusion = run.get("conclusion")
                    if rid in last_seen and last_seen[rid] == status:
                        continue
                    last_seen[rid] = status
                    label = f"  [run {rid}] {run['name']}: {status}"
                    if conclusion:
                        label += f" → {conclusion}"
                    print(label)
                    if status == "completed":
                        finished.append(run)
        except Exception as e:
            print(f"  [poll-err] {e}", file=sys.stderr)

        if finished:
            time.sleep(2)
            return finished

        time.sleep(5)

    print(f"  [TIMEOUT] {timeout_sec}s 内未等到完成", file=sys.stderr)
    return finished


def parse_repo(s: str) -> tuple[str, str]:
    if "/" not in s:
        print(f"[FATAL] 仓库格式应为 owner/repo, 收到 {s}", file=sys.stderr)
        sys.exit(1)
    owner, name = s.split("/", 1)
    return owner, name


def main():
    ap = argparse.ArgumentParser(description="云端采集 workflow 本地触发器")
    ap.add_argument("--repo", default=os.environ.get("RECON_REPO", DEFAULT_REPO),
                    help=f"GitHub 仓库 (默认 {DEFAULT_REPO})")
    ap.add_argument("--task", help="单个任务: subdomain / dns / ports / banners / js / dirs / params")
    ap.add_argument("--all", action="store_true", help="触发全部 7 个 workflow")
    ap.add_argument("--target", required=True, help="目标域名 (如 example.com)")
    ap.add_argument("--wait", action="store_true", help="触发后阻塞等待完成")
    ap.add_argument("--timeout", type=int, default=600, help="等待超时秒数 (默认 600)")
    ap.add_argument("--decode", action="store_true", help="完成后自动调用 recon_decoder 解密")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""),
                    help="GitHub PAT (默认读 env GITHUB_TOKEN)")
    args = ap.parse_args()

    owner, name = parse_repo(args.repo)
    if not args.token:
        print("[FATAL] GITHUB_TOKEN 未设置, 请 setx GITHUB_TOKEN ghp_xxxx", file=sys.stderr)
        sys.exit(1)

    if args.all:
        tasks = list(WORKFLOWS.keys())
    elif args.task:
        if args.task not in WORKFLOWS:
            print(f"[FATAL] 未知任务 {args.task}, 可选: {list(WORKFLOWS.keys())}", file=sys.stderr)
            sys.exit(1)
        tasks = [args.task]
    else:
        ap.error("必须指定 --task 或 --all")

    print(f"[+] 仓库: {args.repo}")
    print(f"[+] 目标: {args.target}")
    print(f"[+] 触发: {tasks}")
    print()

    failed = 0
    for t in tasks:
        if trigger_workflow(args.repo, WORKFLOWS[t], args.target, args.token) != 0:
            failed += 1

    if failed:
        print(f"\n[!] {failed} 个 workflow 触发失败", file=sys.stderr)

    if args.wait:
        print(f"\n[+] 等待 runs 完成 (超时 {args.timeout}s)...")
        runs = wait_runs(args.repo, args.token, args.timeout)
        ok = sum(1 for r in runs if r.get("conclusion") == "success")
        fail = sum(1 for r in runs if r.get("conclusion") == "failure")
        print(f"\n[+] 完成: 成功 {ok}, 失败 {fail}, 总计 {len(runs)}")

    if args.decode:
        print("\n[+] 自动解密...")
        try:
            from aiburp.recon_decoder import decode_all
        except ImportError:
            from recon_decoder import decode_all
        out_dir = os.path.abspath(f"./recon_out/{args.target}")
        ok = decode_all(args.repo, "main", tasks, _load_priv_pem(), out_dir)
        print(f"[+] 解密: {ok}/{len(tasks)} → {out_dir}")


def _load_priv_pem() -> bytes:
    key = os.path.expanduser("~/.recon/recon_private.pem")
    if not os.path.exists(key):
        print(f"[FATAL] 找不到私钥 {key}", file=sys.stderr)
        sys.exit(1)
    with open(key, "rb") as f:
        return f.read()


if __name__ == "__main__":
    main()
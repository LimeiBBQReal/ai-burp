"""查看 GitHub Actions 运行日志."""
import subprocess, json
import urllib.request


def get_token():
    result = subprocess.run(['git', 'credential', 'fill'],
                           input='protocol=https\nhost=github.com\n\n',
                           capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if line.startswith('password='):
            return line[9:]
    raise RuntimeError("无法获取 GitHub token")


def get_jobs(token, run_id):
    url = f"https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/runs/{run_id}/jobs"
    req = urllib.request.Request(url, headers={"Authorization": f"token {token}"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read().decode())


def get_logs(token, job_id):
    # GitHub logs redirect to S3, need to follow with same auth or strip auth on redirect
    import http.client
    url = f"https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/jobs/{job_id}/logs"
    req = urllib.request.Request(url, headers={"Authorization": f"token {token}"})

    # Don't auto-follow redirect (S3 doesn't accept GitHub token)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # don't follow

    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(req, timeout=10)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302):
            # Get redirect URL
            redirect_url = e.headers.get('Location')
            print(f"[LOG] Redirect to: {redirect_url}", file=__import__('sys').stderr)
            # Fetch from S3 without auth
            req2 = urllib.request.Request(redirect_url, headers={"User-Agent": "python"})
            return urllib.request.urlopen(req2, timeout=30).read().decode("utf-8", errors="replace")
        raise


if __name__ == "__main__":
    token = get_token()
    run_id = 28296436238
    jobs = get_jobs(token, run_id)
    for job in jobs['jobs']:
        print(f"\n=== Job: {job['name']} (conclusion: {job['conclusion']}) ===\n")
        logs = get_logs(token, job['id'])
        # 只显示后 5000 字符
        print(logs[-5000:])
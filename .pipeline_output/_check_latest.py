"""查看 GitHub Actions 最近运行."""
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


if __name__ == "__main__":
    token = get_token()
    url = "https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/runs?per_page=3"
    req = urllib.request.Request(url, headers={"Authorization": f"token {token}"})
    data = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
    for r in data['workflow_runs']:
        print(f"#{r['run_number']} {r['event']} {r['created_at'][:19]} status={r['status']} conclusion={r.get('conclusion')}")
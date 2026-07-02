"""触发 proxy-pool workflow 并轮询结果."""
import subprocess, json, time
import urllib.request


def get_token():
    result = subprocess.run(['git', 'credential', 'fill'],
                           input='protocol=https\nhost=github.com\n\n',
                           capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if line.startswith('password='):
            return line[9:]
    raise RuntimeError("无法获取 GitHub token")


def trigger(token):
    url = "https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/workflows/refresh.yml/dispatches"
    req = urllib.request.Request(url, method="POST", data=json.dumps({"ref": "main"}).encode(),
                                headers={"Authorization": f"token {token}",
                                         "Accept": "application/vnd.github+json",
                                         "Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)
    time.sleep(3)
    runs_url = "https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/workflows/refresh.yml/runs?per_page=1"
    req = urllib.request.Request(runs_url, headers={"Authorization": f"token {token}"})
    data = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
    return data['workflow_runs'][0]['id']


def poll(token, run_id, timeout=600):
    url = f"https://api.github.com/repos/LimeiBBQReal/proxy-pool/actions/runs/{run_id}"
    start = time.time()
    while time.time() - start < timeout:
        req = urllib.request.Request(url, headers={"Authorization": f"token {token}"})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
        if data["status"] == "completed":
            return data["conclusion"]
        print(f"  [WAIT] run {run_id}: {data['status']} ({int(time.time()-start)}s)")
        time.sleep(15)
    return "timeout"


if __name__ == "__main__":
    token = get_token()
    print("Triggering workflow...")
    run_id = trigger(token)
    print(f"  Run ID: {run_id}")
    result = poll(token, run_id)
    print(f"  Result: {result}")
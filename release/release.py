#!/usr/bin/env -S python3 -u
import datetime
import http.client
import json
import re
import subprocess
import sys
import time
from pathlib import Path

# Security: No third-party dependencies here!

root = Path(__file__).absolute().parent.parent


def get_json(url: str) -> dict:
    assert url.startswith("https://")
    host, path = re.split(r"(?=/)", url.removeprefix("https://"), maxsplit=1)
    conn = http.client.HTTPSConnection(host)
    conn.request("GET", path, headers={"User-Agent": "mitmproxy/release-bot"})
    resp = conn.getresponse()
    body = resp.read()
    try:
        return json.loads(body)
    except Exception as e:
        raise RuntimeError(body) from e


if __name__ == "__main__":
    version = sys.argv[1]
    assert re.match(r"^\d+\.\d+\.\d+$", version)
    major_version = int(version.split(".")[0])

    print("Working dir clean?", end=" ")
    assert not subprocess.run(["git", "status", "--porcelain"], capture_output=True).stdout
    print("✅")

    print("Main branch CI is passing?", end=" ")
    assert get_json("https://api.github.com/repos/mitmproxy/mitmproxy/commits/main/status")["state"] == "success"
    print("✅")

    print("Updating CHANGELOG.md...", end=" ")
    changelog = root / "CHANGELOG.md"
    date = datetime.date.today().strftime("%d %B %Y")
    title = f"## {date}: mitmproxy {version}"
    cl = changelog.read_text("utf8")
    assert title not in cl
    cl, ok = re.subn(r"(?<=## Unreleased: mitmproxy next)", f"\n\n\n\n{title}", cl)
    assert ok == 1
    changelog.write_text(cl, "utf8")
    print("✅")

    print("Updating web assets...", end=" ")
    subprocess.run(["npm", "ci"], cwd=root / "web", check=True)
    subprocess.run(["npm", "start", "prod"], cwd=root / "web", check=True)
    print("✅")

    print("Updating version...", end=" ")
    version_py = root / "mitmproxy" / "version.py"
    ver = version_py.read_text("utf8")
    ver, ok = re.subn(r'(?<=VERSION = ")[^"]+', version, ver)
    assert ok == 1
    version_py.write_text(ver, "utf8")
    print("✅")

    print("Do release commit...", end=" ")
    subprocess.run(["git", "commit", "-a", "-m", f"mitmproxy {version}"], cwd=root, check=True)
    subprocess.run(["git", "tag", version], cwd=root, check=True)
    print("✅")

    print("Bump version...", end=" ")
    next_dev_version = f"{major_version + 1}.0.0.dev"
    ver, ok = re.subn(r'(?<=VERSION = ")[^"]+', next_dev_version, ver)
    assert ok == 1
    version_py.write_text(ver, "utf8")
    print("✅")

    print("Do reopen commit...", end=" ")
    subprocess.run(["git", "commit", "-a", "-m", f"reopen main for development"], cwd=root, check=True)
    print("✅")

    print("Pushing...", end=" ")
    subprocess.run(["git", "push", "--atomic", "origin", "main", version], cwd=root, check=True)
    print("✅")

    print("Creating release on GitHub...", end=" ")
    subprocess.run(["gh", "release", "create", version,
                    "--title", f"mitmproxy {version}",
                    "--notes-file", "release/github-release-notes.txt"], cwd=root, check=True)
    print("✅")

    print("")
    print("CI is running now. Make sure to approve the workflow: https://github.com/mitmproxy/mitmproxy/actions")

    for _ in range(60):
        time.sleep(3)
        print(".", end="")
    print("")

    print("Checking GitHub Releases...", end=" ")
    gh_releases = get_json("https://api.github.com/repos/mitmproxy/mitmproxy/releases?per_page=1")
    gh_release_version = gh_releases[0]["tag_name"]
    assert gh_release_version == version
    print("✅")

    while True:
        print("Checking PyPI...", end=" ")
        pypi_data = get_json("https://pypi.org/pypi/mitmproxy/json")
        pypi_version = pypi_data["info"]["version"]
        if pypi_version == version:
            print("✅")
            break
        else:
            print(pypi_version)
            time.sleep(10)

    while True:
        print("Checking docs archive...", end=" ")
        conn = http.client.HTTPSConnection("docs.mitmproxy.org")
        conn.request("GET", f"/archive/v{major_version}/")
        resp = conn.getresponse()
        if resp.status == 200:
            print("✅")
            break
        else:
            print(resp.status)
            time.sleep(10)

    while True:
        print(f"Checking Docker ({version} tag)...", end=" ")
        conn = http.client.HTTPSConnection("hub.docker.com")
        conn.request("GET", f"/v2/repositories/mitmproxy/mitmproxy/tags/{version}")
        resp = conn.getresponse()
        if resp.status == 200:
            print("✅")
            break
        else:
            print(resp.status)
            time.sleep(10)

    while True:
        print("Checking Docker (latest tag)...", end=" ")
        docker_latest_data = get_json("https://hub.docker.com/v2/repositories/mitmproxy/mitmproxy/tags/latest")
        docker_last_updated = datetime.datetime.fromisoformat(docker_latest_data["last_updated"].replace("Z", "+00:00"))
        if docker_last_updated > datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2):
            print("✅")
            break
        else:
            print(docker_last_updated.isoformat(timespec='minutes'))
            time.sleep(10)

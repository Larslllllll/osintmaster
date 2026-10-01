import re
import threading
from time import sleep

import httpx

from osintmaster.config import Config
from osintmaster.reports.workspace import make_workspace_server


def test_workspace_launches_local_case_and_browses_result(tmp_path):
    server = make_workspace_server(Config(reports_dir=tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with httpx.Client(follow_redirects=False) as client:
            landing = client.get(base + "/")
            assert landing.status_code == 200
            token = re.search(r'name="token" value="([^"]+)"', landing.text).group(1)
            form = {
                "token": token,
                "targets": "+41791234567\n+41791234568",
                "name": "research",
                "depth": "0",
                "max_requests": "0",
            }
            assert (
                client.post(
                    base + "/runs", data=form, headers={"Origin": "http://evil.example"}
                ).status_code
                == 403
            )
            assert (
                client.post(
                    base + "/runs", data={**form, "token": "wrong"}, headers={"Origin": base}
                ).status_code
                == 403
            )
            started = client.post(base + "/runs", data=form, headers={"Origin": base})
            assert started.status_code == 303
            route = started.headers["location"]
            for _ in range(100):
                job = client.get(base + route + ".json").json()
                if job["status"] != "running":
                    break
                sleep(0.05)
            assert job["status"] == "complete"
            run_id = job["investigation_id"]
            report = client.get(base + f"/runs/{run_id}/report.json").json()
            assert report["target_type"] == "CASE"
            assert report["target"] == "case-research"
            assert len(report["graph"]["investigation"]["seed_entities"]) == 2
            assert "case-research" in client.get(base + "/").text
            assert client.get(base + f"/runs/{run_id}").status_code == 200
            assert client.get(base + "/", headers={"Host": "evil.example"}).status_code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

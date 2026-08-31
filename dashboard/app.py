"""Development static host and same-origin proxy for the Delta-NIDS dashboard."""
from pathlib import Path
import os
import urllib.error
import urllib.request
from flask import Flask, render_template, request, Response
from datetime import datetime
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(ROOT / "static"), template_folder=str(ROOT / "templates"))
API_URL = os.environ.get("DELTA_NIDS_API_URL", "http://127.0.0.1:8080").rstrip("/")


@app.get("/")
def index():
    return render_template("index.html")


@app.route("/api/<path:path>", methods=["GET", "DELETE"])
def proxy_api(path):
    url = f"{API_URL}/api/{path}"
    if request.query_string:
        url += "?" + request.query_string.decode("utf-8")
    try:
        upstream = urllib.request.Request(url, method=request.method, headers={"Accept": "application/json"})
        with urllib.request.urlopen(upstream, timeout=10) as response:
            payload = response.read()
            headers = {"Content-Type": response.headers.get_content_type()}
            if path in {"alerts/export", "traffic/export"}:
                kind = "alerts" if path == "alerts/export" else "traffic"
                date = datetime.now(ZoneInfo("Asia/Kolkata")).date().isoformat()
                headers["Content-Disposition"] = f'attachment; filename="delta-nids-{kind}-{date}.json"'
            return Response(payload, status=response.status, headers=headers)
    except urllib.error.HTTPError as error:
        return Response(error.read() or b'{"error":"upstream API error"}', status=error.code, content_type="application/json")
    except (urllib.error.URLError, OSError):
        return Response(b'{"error":"Delta-NIDS API unavailable"}', status=502, content_type="application/json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("DELTA_NIDS_DASHBOARD_PORT", "8081")), debug=False, use_reloader=False)

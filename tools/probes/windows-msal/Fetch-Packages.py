"""Fetch this protocol's seven public packages in WSL; never access account state."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)


def main():
    root, revision = Path(sys.argv[1]), sys.argv[2]
    attempt = root / "fetch-1"
    attempt.mkdir()  # Existing or uncertain consumption must be reconciled, never reset.
    write_new(attempt / "start.json", {"revision": revision, "utc": utc()})
    watchdog = threading.Timer(120, lambda: os._exit(124))
    watchdog.daemon = True
    watchdog.start()
    result = {"revision": revision, "status": "fetch-failed", "packages": []}
    try:
        feed = root / "public-feed"
        feed.mkdir()
        project = ET.parse(Path(__file__).with_name("WindowsMsalProbe.csproj"))
        total = 0
        for reference in project.findall(".//PackageReference"):
            name = reference.attrib["Include"].lower()
            version = reference.attrib["Version"].strip("[]")
            filename = f"{name}.{version}.nupkg"
            url = f"https://api.nuget.org/v3-flatcontainer/{name}/{version}/{filename}"
            partial = feed / (filename + ".partial")
            size, digest = 0, hashlib.sha512()
            with urllib.request.urlopen(url, timeout=15) as response, partial.open("xb") as output:
                destination = urllib.parse.urlparse(response.url)
                if destination.scheme != "https" or destination.hostname not in {
                    "api.nuget.org", "globalcdn.nuget.org"
                }:
                    raise ValueError("Unexpected package endpoint")
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    total += len(chunk)
                    if size > 100 * 1024 * 1024 or total > 200 * 1024 * 1024:
                        raise ValueError("Package size bound exceeded")
                    digest.update(chunk)
                    output.write(chunk)
            partial.rename(feed / filename)
            result["packages"].append({"name": name, "version": version, "bytes": size,
                                       "sha512": digest.hexdigest()})
        result["status"] = "packages-fetched"
    except Exception:
        pass  # Retain partial public artifacts and a fixed failure outcome, not diagnostics.
    finally:
        result["utc"] = utc()
        write_new(attempt / "result.json", result)
        watchdog.cancel()
    return 0 if result["status"] == "packages-fetched" else 1


if __name__ == "__main__":
    sys.exit(main())

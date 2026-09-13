"""Fetch an admitted list of public packages; invoked only by run_managed.py."""

import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Package redirects are outside this protocol")


def main():
    destination = Path(sys.argv[1])
    # Reserve the entire allowance before the parent starts this process. A failure
    # therefore cannot lose consumption, even if it happens before a body is saved.
    remaining = 128 * 1024 * 1024
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for specification in sys.argv[2:]:
        if not re.fullmatch(r"[a-z0-9_.-]+=[0-9]+(?:\.[0-9]+){1,3}(?:-[a-z0-9.-]+)?", specification):
            raise ValueError("Invalid exact package specification")
        name, version = specification.split("=")
        filename = f"{name}.{version}.nupkg"
        url = f"https://api.nuget.org/v3-flatcontainer/{name}/{version}/{filename}"
        with opener.open(url, timeout=15) as response:
            length = int(response.headers["Content-Length"])
            if response.status != 200 or not 0 < length <= remaining:
                raise ValueError("Package content exceeds the reserved allowance")
            remaining -= length
            partial = destination / (filename + ".partial")
            digest, received = hashlib.sha512(), 0
            with partial.open("xb") as output:
                while received < length:
                    chunk = response.read(min(65536, length - received))
                    if not chunk:
                        raise ValueError("Incomplete package")
                    received += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
            # No extraction or execution here. NuGet and a provenance review consume
            # the original public archive after a successful fetch.
            partial.rename(destination / filename)
            print(json.dumps({"package": specification, "bytes": received,
                              "sha512": digest.hexdigest()}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never echo an inherited path or arbitrary remote error response.
        print("Public package preparation failed", file=sys.stderr)
        sys.exit(1)

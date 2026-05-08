import json
import os

os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("LOG_LEVEL", "ERROR")

import lambda_function as lf


class Ctx:
    aws_request_id = "local-api-proxy-test"


def main():
    lf._load_policy_for_domain = lambda _domain: {
        "version": 1,
        "sources": [
            {
                "id": "itunes-song-search",
                "method": "GET",
                "url": "https://itunes.apple.com/search",
                "allowedInputFields": ["term", "entity", "limit"],
                "response": {"allowedFields": ["resultCount", "results"]},
            }
        ],
        "actions": [],
    }
    lf._fetch_upstream = lambda **_kwargs: {
        "resultCount": 2,
        "results": [{"trackName": "Looking Bass"}, {"trackName": "Melancholy"}],
        "debug": "filtered",
    }

    event = {
        "rawPath": "/api-proxy/read",
        "isBase64Encoded": False,
        "body": json.dumps({
            "domain": "music.lynxpardelle.com",
            "sourceId": "itunes-song-search",
            "input": {"term": "lynx pardelle", "entity": "song", "limit": 2},
        }),
    }

    response = lf.lambda_handler(event, Ctx())
    print("Status:", response.get("statusCode"))
    print("Body:", response.get("body"))


if __name__ == "__main__":
    main()

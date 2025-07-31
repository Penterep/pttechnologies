"""
helpers.responses

Defines structured containers for passing HTTP responses between modules.
Used to keep module interfaces clean and avoid bloated argument lists.
"""

from dataclasses import dataclass
from requests.models import Response
from typing import Optional

from ptlibs.http.raw_http_client import RawHttpResponse

@dataclass
class StoredResponses:
    """
    Container for commonly used HTTP responses passed between modules.

    Attributes:
        resp_hp (Response): The initial response from the homepage or root URL.
        resp_404 (Response): A known 404 response used as a baseline for comparison.
        raw_resp_400 (Optional[RawHttpResponse]): A raw HTTP 400-like response from a low-level client,
            used for comparing malformed or blocked requests (e.g. for fingerprinting).
            May be None if the raw request failed or was not performed.
        resp_favicon (Optional[Response]): The response from the '/favicon.ico' path,
            used to detect web server variations behind a load balancer.
        long_resp (Optional[Response]): The response from a deliberately long URL (e.g., 5000 'a' characters),
            typically returning a 400 Bad Request used for additional fingerprinting.
            May be None if the request failed or was not performed.
    """
    resp_hp: Response
    resp_404: Response
    raw_resp_400: Optional[RawHttpResponse]
    resp_favicon: Optional[Response]
    long_resp: Optional[Response]
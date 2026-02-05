#!/usr/bin/env python3
"""
TLS Fingerprint Bypass Worker
FastAPI server using curl_cffi for browser TLS impersonation

Copyright (c) 2024 TLS Bypass Project
Licensed under the MIT License
"""

import argparse
import asyncio
import base64
import logging
import sys
import time
from typing import Optional, Dict, List, Any

# Check dependencies
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    import uvicorn
except ImportError:
    print("ERROR: FastAPI not installed. Run: pip install fastapi uvicorn", file=sys.stderr)
    sys.exit(1)

try:
    from curl_cffi.requests import AsyncSession
except ImportError:
    print("ERROR: curl_cffi not installed. Run: pip install curl_cffi", file=sys.stderr)
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="TLS Bypass Worker",
    description="Proxy server for TLS fingerprint impersonation using curl_cffi",
    version="1.0.0"
)

# Global session with connection pooling
session: Optional[AsyncSession] = None

# Supported impersonation targets (curl_cffi v0.11+)
SUPPORTED_TARGETS = [
    # Generic (auto-select latest)
    "chrome", "firefox", "safari", "chrome_android", "safari_ios",
    # Chrome Desktop
    "chrome136", "chrome133a", "chrome131", "chrome124", "chrome123",
    "chrome120", "chrome119", "chrome116", "chrome110", "chrome107",
    "chrome104", "chrome101", "chrome100", "chrome99",
    # Chrome Android
    "chrome131_android", "chrome99_android",
    # Safari Desktop
    "safari260", "safari184", "safari180", "safari170", "safari155", "safari153",
    # Safari iOS
    "safari260_ios", "safari184_ios", "safari180_ios", "safari172_ios",
    # Firefox
    "firefox133",
    # Edge
    "edge101", "edge99",
    # Tor
    "tor145"
]


class ProxyRequest(BaseModel):
    """Request model for proxy endpoint"""
    method: str = Field(..., description="HTTP method (GET, POST, PUT, DELETE, etc.)")
    url: str = Field(..., description="Full URL to request")
    headers: Optional[Dict[str, str]] = Field(default=None, description="HTTP headers")
    body: Optional[str] = Field(default=None, description="Request body (plain text or base64)")
    body_encoding: Optional[str] = Field(default=None, description="Body encoding: 'base64' or None for plain text")
    impersonate: str = Field(default="chrome", description="Browser to impersonate")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    max_redirects: int = Field(default=10, description="Maximum number of redirects to follow")
    auto_user_agent: bool = Field(default=True, description="Auto-set User-Agent based on impersonated browser")


class ProxyResponse(BaseModel):
    """Response model for proxy endpoint"""
    status_code: int
    reason: str
    headers: Dict[str, str]
    body: str
    body_encoding: str  # "base64" for binary, "text" for text
    elapsed_ms: float
    final_url: Optional[str] = None  # Final URL after redirects


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    session_active: bool
    version: str


class TargetsResponse(BaseModel):
    """Supported targets response"""
    targets: List[str]
    categories: Dict[str, List[str]]


@app.on_event("startup")
async def startup():
    """Initialize connection pool on startup"""
    global session
    session = AsyncSession(timeout=60)
    logger.info("TLS Bypass Worker started - AsyncSession initialized with connection pooling")
    logger.info(f"Supported impersonation targets: {len(SUPPORTED_TARGETS)}")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    global session
    if session:
        await session.close()
        logger.info("AsyncSession closed")


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for connection verification"""
    return HealthResponse(
        status="ok",
        session_active=session is not None,
        version="1.0.0"
    )


@app.get("/targets", response_model=TargetsResponse)
async def list_targets():
    """List all supported impersonation targets organized by category"""
    categories = {
        "generic": ["chrome", "firefox", "safari", "chrome_android", "safari_ios"],
        "chrome_desktop": [t for t in SUPPORTED_TARGETS if t.startswith("chrome") and "android" not in t and t not in ["chrome", "chrome_android"]],
        "chrome_android": [t for t in SUPPORTED_TARGETS if "chrome" in t and "android" in t],
        "safari_desktop": [t for t in SUPPORTED_TARGETS if t.startswith("safari") and "ios" not in t and t != "safari"],
        "safari_ios": [t for t in SUPPORTED_TARGETS if "safari" in t and "ios" in t],
        "firefox": [t for t in SUPPORTED_TARGETS if t.startswith("firefox") and t != "firefox"],
        "edge": [t for t in SUPPORTED_TARGETS if t.startswith("edge")],
        "tor": [t for t in SUPPORTED_TARGETS if t.startswith("tor")]
    }
    return TargetsResponse(targets=SUPPORTED_TARGETS, categories=categories)


@app.post("/proxy", response_model=ProxyResponse)
async def proxy_request(request: ProxyRequest):
    """
    Forward request with TLS fingerprint impersonation.

    This endpoint accepts HTTP request details and forwards them using curl_cffi
    with the specified browser impersonation to bypass TLS fingerprinting.
    """
    global session

    if session is None:
        raise HTTPException(status_code=503, detail="Session not initialized")

    # Validate impersonation target
    if request.impersonate not in SUPPORTED_TARGETS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported impersonate target: '{request.impersonate}'. "
                   f"Use GET /targets to see supported values."
        )

    # Decode body if base64 encoded
    body_data = None
    if request.body:
        if request.body_encoding == "base64":
            try:
                body_data = base64.b64decode(request.body)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid base64 body: {e}")
        else:
            body_data = request.body.encode('utf-8')

    # Prepare headers - filter out headers that curl_cffi will set automatically
    headers = request.headers or {}
    headers_to_remove = [
        'content-length', 'host', 'connection',
        'accept-encoding', 'transfer-encoding'
    ]

    # If auto_user_agent is enabled, remove user-agent so curl_cffi sets it automatically
    if request.auto_user_agent:
        headers_to_remove.append('user-agent')

    filtered_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in headers_to_remove
    }

    try:
        start_time = time.time()

        # Make request with impersonation
        response = await session.request(
            method=request.method.upper(),
            url=request.url,
            headers=filtered_headers if filtered_headers else None,
            data=body_data,
            impersonate=request.impersonate,
            timeout=request.timeout,
            verify=request.verify_ssl,
            allow_redirects=request.follow_redirects,
            max_redirects=request.max_redirects
        )

        elapsed_ms = (time.time() - start_time) * 1000

        # Prepare response headers (convert to dict)
        response_headers = {}
        for key, value in response.headers.items():
            # Handle multiple headers with same name
            if key in response_headers:
                response_headers[key] = f"{response_headers[key]}, {value}"
            else:
                response_headers[key] = value

        # Determine if content is text or binary based on Content-Type
        content_type = response_headers.get('content-type', response_headers.get('Content-Type', '')).lower()

        # Text content types that should be decoded as text
        text_types = (
            'text/', 'application/json', 'application/xml', 'application/javascript',
            'application/x-javascript', 'application/ecmascript', 'application/x-www-form-urlencoded',
            '+json', '+xml', 'application/ld+json'
        )

        is_text_content = any(t in content_type for t in text_types)

        # Always use base64 for binary content for safety
        if is_text_content:
            try:
                body_content = response.text
                body_encoding = "text"
            except (UnicodeDecodeError, AttributeError, LookupError):
                # Fallback to base64 if text decoding fails
                body_encoding = "base64"
                body_content = base64.b64encode(response.content).decode('ascii')
        else:
            # Binary content - always use base64
            body_encoding = "base64"
            body_content = base64.b64encode(response.content).decode('ascii')

        # Get reason phrase
        reason = "OK"
        if hasattr(response, 'reason'):
            reason = response.reason or "OK"
        elif response.status_code in HTTP_STATUS_PHRASES:
            reason = HTTP_STATUS_PHRASES[response.status_code]

        logger.info(
            f"[{request.impersonate}] {request.method} {request.url} -> "
            f"{response.status_code} ({elapsed_ms:.1f}ms)"
        )

        return ProxyResponse(
            status_code=response.status_code,
            reason=reason,
            headers=response_headers,
            body=body_content,
            body_encoding=body_encoding,
            elapsed_ms=elapsed_ms,
            final_url=str(response.url) if response.url != request.url else None
        )

    except asyncio.TimeoutError:
        logger.error(f"Request timeout: {request.url}")
        raise HTTPException(status_code=504, detail="Request timeout")
    except Exception as e:
        logger.error(f"Request failed: {request.url} - {e}")
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)}")


@app.post("/batch")
async def batch_proxy(requests: List[ProxyRequest]):
    """
    Execute multiple requests concurrently.

    Useful for batch operations where multiple requests need to be made
    with TLS fingerprint impersonation.
    """
    tasks = [proxy_request(req) for req in requests]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    responses = []
    for i, result in enumerate(results):
        if isinstance(result, HTTPException):
            responses.append({
                "error": True,
                "status_code": result.status_code,
                "detail": result.detail
            })
        elif isinstance(result, Exception):
            responses.append({
                "error": True,
                "status_code": 500,
                "detail": str(result)
            })
        else:
            responses.append({
                "error": False,
                **result.model_dump()
            })

    return {"responses": responses, "total": len(responses)}


# HTTP status code phrases
HTTP_STATUS_PHRASES = {
    100: "Continue",
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    206: "Partial Content",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    429: "Too Many Requests",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


def main():
    """Main entry point for the worker server"""
    parser = argparse.ArgumentParser(
        description="TLS Bypass Worker Server - Browser TLS fingerprint impersonation proxy"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1 for security)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8787,
        help="Port to bind to (default: 8787)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Log level (default: info)"
    )

    args = parser.parse_args()

    logger.info(f"Starting TLS Bypass Worker on {args.host}:{args.port}")
    logger.info(f"Supported browsers: {len(SUPPORTED_TARGETS)} targets")

    uvicorn.run(
        "worker:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level,
        access_log=True
    )


if __name__ == "__main__":
    main()

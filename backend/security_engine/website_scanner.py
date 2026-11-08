import http.client
import ipaddress
import re
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunsplit


SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "medium"),
    "content-security-policy": ("CSP", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "low"),
    "x-frame-options": ("X-Frame-Options", "low"),
    "referrer-policy": ("Referrer-Policy", "low"),
    "permissions-policy": ("Permissions-Policy", "low"),
}
REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 6
MAX_HTML_BYTES = 512_000
MAX_REPORTED_PAGE_REFERENCES = 50
SUSPICIOUS_REDIRECT_PORTS = {21, 22, 23, 25, 110, 143, 445, 3389}

FINDING_RECOMMENDATIONS = {
    "https_redirect_downgrade": "Keep all redirects on HTTPS and remove any downgrade to HTTP.",
    "cross_origin_redirect": "Verify that each redirect destination is expected and controlled by the site operator.",
    "redirect_limit_reached": "Review the redirect sequence and remove unnecessary or looping redirects.",
    "redirect_loop_detected": "Correct the redirect configuration so the destination resolves without revisiting a prior URL.",
    "suspicious_redirect_destination": "Verify the redirect destination and its business purpose through a trusted channel.",
    "redirect_target_blocked": "Review the redirect target from a trusted environment; the scanner did not connect to it.",
    "https_not_enforced": "Redirect HTTP requests to HTTPS and keep the full redirect path on the intended domain.",
    "mixed_content_detected": "Serve active and passive page resources over HTTPS; inspect the listed origins.",
    "insecure_form_action": "Submit forms only to HTTPS endpoints controlled by the site operator.",
    "cookie_missing_secure": "Set Secure on cookies that should only be sent over HTTPS.",
    "cookie_missing_httponly": "Set HttpOnly on cookies that do not need to be read by client-side code.",
    "cookie_missing_samesite": "Set an appropriate SameSite policy for the cookie's intended use.",
    "cookie_samesite_none_without_secure": "Add Secure to cookies using SameSite=None, and confirm cross-site use is necessary.",
    "missing_strict_transport_security": "After verifying HTTPS coverage, configure an appropriate Strict-Transport-Security policy.",
    "missing_content_security_policy": "Define and test a Content-Security-Policy suited to the site's resources.",
    "missing_x_frame_options": "Set an appropriate frame-ancestors CSP directive or X-Frame-Options policy.",
    "missing_x_content_type_options": "Set X-Content-Type-Options to nosniff.",
    "missing_referrer_policy": "Set a Referrer-Policy appropriate to the site's privacy requirements.",
    "missing_permissions_policy": "Restrict browser features with a Permissions-Policy appropriate to the site.",
    "server_header_exposed": "Remove or minimize unnecessary server-version details in response headers.",
    "powered_by_header_exposed": "Remove the X-Powered-By response header if it is not required.",
}


class _PageResourceParser(HTMLParser):
    RESOURCE_TAGS = {
        "audio",
        "embed",
        "iframe",
        "img",
        "input",
        "link",
        "object",
        "script",
        "source",
        "track",
        "video",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.mixed_resources = []
        self.insecure_forms = []
        self.mixed_resource_count = 0
        self.insecure_form_count = 0
        self._insecure_form_hosts = set()
        self._in_style_block = False

    def handle_starttag(self, tag, attrs):
        if tag == "style":
            self._in_style_block = True
        attributes = dict(attrs)
        if tag in self.RESOURCE_TAGS:
            for name in ("src", "data"):
                value = attributes.get(name)
                if value:
                    self._add_if_http(value, tag)
            if tag == "link" and attributes.get("href"):
                rel = (attributes.get("rel") or "").lower().split()
                if rel and any(token in rel for token in ("stylesheet", "preload", "icon")):
                    self._add_if_http(attributes["href"], tag)
            srcset = attributes.get("srcset")
            if srcset:
                for candidate in srcset.split(","):
                    candidate_parts = candidate.strip().split()
                    if candidate_parts:
                        self._add_if_http(candidate_parts[0], tag)
        if tag == "form" and attributes.get("action"):
            try:
                parsed = urlparse(attributes["action"])
            except ValueError:
                parsed = None
            hostname = parsed.hostname.lower() if parsed and parsed.hostname else None
            if (
                parsed
                and parsed.scheme.lower() == "http"
                and hostname
                and hostname not in self._insecure_form_hosts
            ):
                self._insecure_form_hosts.add(hostname)
                self.insecure_form_count += 1
                if len(self.insecure_forms) < MAX_REPORTED_PAGE_REFERENCES:
                    self.insecure_forms.append(hostname)

        style = attributes.get("style", "")
        for value in re.findall(r"url\(\s*['\"]?(.*?)['\"]?\s*\)", style, re.IGNORECASE):
            self._add_if_http(value, "inline-style")

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style_block = False

    def handle_data(self, data):
        if self._in_style_block:
            for value in re.findall(
                r"url\(\s*['\"]?(.*?)['\"]?\s*\)", data, re.IGNORECASE
            ):
                self._add_if_http(value, "style-block")

    def _add_if_http(self, value, tag):
        try:
            parsed = urlparse(value.strip())
        except ValueError:
            return
        if parsed.scheme.lower() == "http" and parsed.hostname:
            self.mixed_resource_count += 1
            if len(self.mixed_resources) < MAX_REPORTED_PAGE_REFERENCES:
                self.mixed_resources.append({
                    "element": tag,
                    "hostname": parsed.hostname.lower(),
                })


def _inspect_page_html(
    url: str,
    content_type: str,
    content_encoding: str,
    body: bytes,
    truncated: bool,
) -> dict:
    if urlparse(url).scheme.lower() != "https":
        return {
            "status": "not_applicable",
            "resources": [],
            "resource_count": 0,
            "insecure_forms": [],
            "form_count": 0,
            "truncated": False,
        }
    if not any(
        kind in (content_type or "").lower()
        for kind in ("text/html", "application/xhtml+xml")
    ):
        return {
            "status": "not_applicable",
            "resources": [],
            "resource_count": 0,
            "insecure_forms": [],
            "form_count": 0,
            "truncated": False,
        }
    if content_encoding and content_encoding.lower() != "identity":
        return {
            "status": "unavailable",
            "resources": [],
            "resource_count": 0,
            "insecure_forms": [],
            "form_count": 0,
            "truncated": False,
        }
    parser = _PageResourceParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    parser.close()
    output_truncated = (
        truncated
        or parser.mixed_resource_count > len(parser.mixed_resources)
        or parser.insecure_form_count > len(parser.insecure_forms)
    )
    return {
        "status": "partial" if output_truncated else "checked",
        "resources": parser.mixed_resources,
        "resource_count": parser.mixed_resource_count,
        "insecure_forms": parser.insecure_forms,
        "form_count": parser.insecure_form_count,
        "truncated": output_truncated,
    }


def _redirect_key(url: str) -> tuple:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError:
        port = -1
    port = port or (443 if parsed.scheme.lower() == "https" else 80)
    return parsed.scheme.lower(), hostname, port, parsed.path or "/", parsed.query


def _origin(url: str) -> tuple:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    return scheme, hostname, port or (443 if scheme == "https" else 80)


class BlockedDestinationError(ValueError):
    pass


def _resolve_public_addresses(hostname: str, port: int) -> list[tuple]:
    try:
        addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise

    if not addresses:
        raise socket.gaierror(f"No addresses found for {hostname}.")

    public_addresses = []
    seen = set()
    for family, socktype, protocol, _canonical_name, sockaddr in addresses:
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            raise BlockedDestinationError(
                "Private or non-public IP address is blocked."
            )
        key = (family, socktype, protocol, sockaddr)
        if key not in seen:
            seen.add(key)
            public_addresses.append((family, socktype, protocol, sockaddr))

    return public_addresses


def is_public_host(hostname: str, port: int = 443) -> bool:
    try:
        if ipaddress.ip_address(hostname).is_global:
            return True
        return False
    except ValueError:
        try:
            _resolve_public_addresses(hostname, port)
            return True
        except (socket.gaierror, OSError, ValueError):
            return False


def validate_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False

        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        if port != (80 if parsed.scheme == "http" else 443):
            return False

        _resolve_public_addresses(parsed.hostname, port)
        return True
    except BlockedDestinationError:
        raise
    except socket.gaierror:
        raise
    except (ValueError, OSError):
        return False


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, port: int, addresses: list[tuple], secure: bool):
        super().__init__(hostname, port, timeout=8.0)
        self.addresses = addresses
        self.ssl_context = ssl.create_default_context() if secure else None

    def connect(self) -> None:
        last_error = None
        for family, socktype, protocol, sockaddr in self.addresses:
            connection = socket.socket(family, socktype, protocol)
            try:
                connection.settimeout(5.0)
                connection.connect(sockaddr)
                connection.settimeout(8.0)
                self.sock = (
                    self.ssl_context.wrap_socket(
                        connection,
                        server_hostname=self.host,
                    )
                    if self.ssl_context
                    else connection
                )
                return
            except (OSError, ssl.SSLError) as error:
                last_error = error
                connection.close()

        if last_error:
            raise last_error
        raise OSError("Could not connect to the validated address.")


def _request_once(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("A valid hostname is required.")
    port = parsed.port or (80 if parsed.scheme == "http" else 443)
    addresses = _resolve_public_addresses(hostname, port)
    connection = _PinnedHTTPConnection(
        hostname,
        port,
        addresses,
        parsed.scheme == "https",
    )
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": parsed.netloc,
                "Range": f"bytes=0-{MAX_HTML_BYTES}",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "User-Agent": "CYBERNOVA-SecurityScanner/1.0",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        try:
            headers = {}
            set_cookie_headers = []
            for name, value in response.getheaders():
                lowered_name = name.lower()
                if lowered_name == "set-cookie":
                    set_cookie_headers.append(value)
                headers[lowered_name] = value
            body = b""
            body_truncated = False
            content_type = headers.get("content-type", "").lower()
            if "text/html" in content_type or "application/xhtml+xml" in content_type:
                body = response.read(MAX_HTML_BYTES + 1)
                if len(body) > MAX_HTML_BYTES:
                    body = body[:MAX_HTML_BYTES]
                    body_truncated = True
            return {
                "http_status": response.status,
                "headers": headers,
                "set_cookie_headers": set_cookie_headers,
                "body": body,
                "body_truncated": body_truncated,
            }
        finally:
            response.close()
    finally:
        connection.close()


def _request_chain(start_url: str) -> dict:
    current_url = start_url
    redirects = []
    set_cookie_headers = []
    visited_urls = set()

    for _ in range(MAX_REDIRECTS + 1):
        key = _redirect_key(current_url)
        if key in visited_urls:
            return {
                "status": "redirect_loop",
                "error": "A previously visited URL was encountered in the redirect chain.",
                "redirects": redirects,
                "final_url": current_url,
            }
        visited_urls.add(key)
        try:
            is_valid = validate_url(current_url)
        except BlockedDestinationError as error:
            return {
                "status": "blocked",
                "error": str(error),
                "redirects": redirects,
                "final_url": current_url,
            }
        except socket.gaierror:
            return {
                "status": "unavailable",
                "error": "Could not resolve website hostname.",
                "redirects": redirects,
                "final_url": current_url,
            }

        if not is_valid:
            return {
                "status": "blocked",
                "error": "URL or redirect to an invalid destination was blocked.",
                "redirects": redirects,
                "final_url": current_url,
            }

        try:
            response = _request_once(current_url)
        except BlockedDestinationError as error:
            return {
                "status": "blocked",
                "error": str(error),
                "redirects": redirects,
                "final_url": current_url,
            }
        except socket.timeout:
            return {
                "status": "unavailable",
                "error": "Website request timed out.",
                "redirects": redirects,
                "final_url": current_url,
            }
        except socket.gaierror:
            return {
                "status": "unavailable",
                "error": "Could not resolve website hostname.",
                "redirects": redirects,
                "final_url": current_url,
            }
        except (http.client.HTTPException, ssl.SSLError, OSError):
            return {
                "status": "unavailable",
                "error": "Could not connect to website.",
                "redirects": redirects,
                "final_url": current_url,
            }
        headers = response["headers"]
        set_cookie_headers.extend(response["set_cookie_headers"])

        location = headers.get("location")
        if response["http_status"] in REDIRECT_CODES and location:
            next_url = urljoin(current_url, location)
            redirects.append({
                "from": current_url,
                "to": next_url,
                "status": response["http_status"],
            })
            current_url = next_url
            continue

        return {
            "status": "completed",
            "http_status": response["http_status"],
            "final_url": current_url,
            "headers": headers,
            "set_cookie_headers": set_cookie_headers,
            "body": response.get("body", b""),
            "body_truncated": response.get("body_truncated", False),
            "redirects": redirects,
            "error": None,
        }

    return {
        "status": "redirect_limit",
        "error": "The website exceeded the redirect limit.",
        "redirects": redirects,
        "final_url": current_url,
    }


def _http_probe_url(https_url: str) -> str:
    parsed = urlparse(https_url)
    hostname = parsed.hostname or ""
    if ":" in hostname:
        hostname = f"[{hostname}]"
    netloc = f"{hostname}:80"
    return urlunsplit(("http", netloc, parsed.path or "/", parsed.query, ""))


def _inspect_cookies(cookie_headers: list[str]) -> list[dict]:
    cookies = []
    for header in cookie_headers:
        parts = [part.strip() for part in header.split(";")]
        name, separator, _ = parts[0].partition("=")
        if not separator or not name:
            continue

        attributes = {}
        for item in parts[1:]:
            key, separator, value = item.partition("=")
            attributes[key.strip().lower()] = value.strip() if separator else None
        same_site = attributes.get("samesite")
        secure = "secure" in attributes
        http_only = "httponly" in attributes
        cookies.append({
            "name": name,
            "secure": secure,
            "http_only": http_only,
            "same_site": same_site,
        })

    return cookies


def _severity_risk(findings: list[dict]) -> int:
    points = {"high": 30, "medium": 15, "low": 5}
    unique_codes = {}
    for index, finding in enumerate(findings):
        key = finding.get("code") or f"finding-{index}"
        unique_codes[key] = max(
            unique_codes.get(key, 0),
            points.get(finding.get("severity"), 0),
        )
    return min(sum(unique_codes.values()), 100)


def scan_website(url: str) -> dict:
    result = {
        "url": url,
        "status": "unknown",
        "http_status": None,
        "final_url": None,
        "redirects": [],
        "redirect_analysis": None,
        "redirect_status": "unavailable",
        "https_enforced": None,
        "https_enforcement": {"status": "unavailable"},
        "security_headers": {},
        "security_header_status": "unavailable",
        "missing_headers": [],
        "cookies": [],
        "cookie_status": "unavailable",
        "mixed_content": {
            "status": "unavailable",
            "resources": [],
            "resource_count": 0,
            "insecure_forms": [],
            "form_count": 0,
            "truncated": False,
        },
        "server": None,
        "powered_by": None,
        "findings": [],
        "finding_details": [],
        "risk_score": None,
        "error": None,
    }

    def add_finding(
        code: str,
        title: str,
        severity: str,
        evidence: str,
        classification: str = "observed_configuration",
    ) -> None:
        finding = {
            "code": code,
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "source": "website_assessment",
            "classification": classification,
            "recommendation": FINDING_RECOMMENDATIONS.get(
                code,
                "Review this observed security configuration and apply the site's appropriate security controls.",
            ),
        }
        result["finding_details"].append(finding)
        result["findings"].append(title)

    if not isinstance(url, str) or not url.strip():
        result.update(status="invalid_url", error="A valid URL is required.")
        return result

    requested_url = url.strip()
    parsed = urlparse(requested_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        result.update(status="invalid_url", error="A valid HTTP or HTTPS URL is required.")
        return result
    if parsed.username or parsed.password:
        result.update(status="blocked", error="URLs containing credentials are not allowed.")
        return result

    try:
        scan = _request_chain(requested_url)
        result.update({
            "status": scan["status"],
            "http_status": scan.get("http_status"),
            "final_url": scan.get("final_url"),
            "redirects": scan.get("redirects", []),
            "error": scan.get("error"),
        })

        hops = result["redirects"]
        result["redirect_status"] = (
            "checked" if scan["status"] == "completed" else "partial" if hops else "unavailable"
        )
        downgrade = any(
            urlparse(hop["from"]).scheme == "https"
            and urlparse(hop["to"]).scheme == "http"
            for hop in hops
        )
        cross_origin = sum(
            _origin(hop["from"]) != _origin(hop["to"])
            for hop in hops
        )
        if hops:
            suspicious_patterns = []
            for hop in hops:
                target = urlparse(hop["to"])
                try:
                    ipaddress.ip_address(target.hostname or "")
                    is_ip_target = True
                except ValueError:
                    is_ip_target = False
                if is_ip_target:
                    suspicious_patterns.append({
                        "type": "redirect_to_ip_address",
                        "hostname": target.hostname,
                    })
                try:
                    target_port = target.port
                except ValueError:
                    target_port = None
                if target_port in SUSPICIOUS_REDIRECT_PORTS:
                    suspicious_patterns.append({
                        "type": "redirect_to_unusual_service_port",
                        "port": target_port,
                        "hostname": target.hostname,
                    })
            result["redirect_analysis"] = {
                "count": len(hops),
                "final_url": result["final_url"],
                "cross_origin_count": cross_origin,
                "https_downgrade": downgrade,
                "loop_detected": scan["status"] == "redirect_loop",
                "suspicious_patterns": suspicious_patterns,
                "chain": hops,
            }
        if downgrade:
            add_finding(
                "https_redirect_downgrade",
                "Redirect chain downgrades from HTTPS to HTTP.",
                "high",
                "At least one redirect in the observed chain changed from HTTPS to HTTP.",
                "confirmed_transport_configuration",
            )
        if cross_origin:
            add_finding(
                "cross_origin_redirect",
                "Website redirects to another origin.",
                "low",
                f"The observed redirect chain contains {cross_origin} origin change(s).",
                "observed_behavior",
            )
        for pattern in (
            result["redirect_analysis"]["suspicious_patterns"]
            if result["redirect_analysis"]
            else []
        ):
            add_finding(
                "suspicious_redirect_destination",
                "Redirect destination uses an IP address or unusual service port.",
                "medium",
                (
                    f"Observed redirect destination hostname {pattern['hostname']} "
                    f"with pattern {pattern['type']}."
                ),
                "observed_behavior_requiring_review",
            )
        if scan["status"] == "blocked" and hops:
            add_finding(
                "redirect_target_blocked",
                "A redirect destination was blocked by scanner safety checks.",
                "medium",
                (
                    f"Redirect destination {result['final_url']} was not requested "
                    "because it used a private/non-public address, unsupported scheme, "
                    "or disallowed port."
                ),
                "blocked_untrusted_destination",
            )

        if scan["status"] != "completed":
            if scan["status"] == "redirect_loop":
                result["redirect_analysis"] = result["redirect_analysis"] or {
                    "count": len(hops),
                    "final_url": result["final_url"],
                    "cross_origin_count": cross_origin,
                    "https_downgrade": downgrade,
                    "loop_detected": True,
                    "suspicious_patterns": [],
                    "chain": hops,
                }
                add_finding(
                    "redirect_loop_detected",
                    "A redirect loop was detected.",
                    "medium",
                    f"The redirect chain revisited {result['final_url']}.",
                    "confirmed_configuration_issue",
                )
            elif scan["status"] == "redirect_limit":
                add_finding(
                    "redirect_limit_reached",
                    "Website exceeded the redirect limit.",
                    "medium",
                    f"More than {MAX_REDIRECTS} redirects were observed before a final response.",
                    "confirmed_configuration_issue",
                )
            if result["finding_details"]:
                result["risk_score"] = _severity_risk(result["finding_details"])
            return result

        headers = scan["headers"]
        final_url = scan["final_url"]
        final_is_https = urlparse(final_url).scheme == "https"
        original_is_http = parsed.scheme == "http"
        result["security_header_status"] = "checked"
        result["security_headers"] = {
            header: None for header in SECURITY_HEADERS
        }

        for header, (display_name, severity) in SECURITY_HEADERS.items():
            if header == "strict-transport-security" and not final_is_https:
                result["security_headers"][header] = None
                continue
            present = header in headers
            result["security_headers"][header] = present
            if not present:
                csp = headers.get("content-security-policy", "").lower()
                if header == "x-frame-options" and "frame-ancestors" in csp:
                    continue
                result["missing_headers"].append(display_name)
                add_finding(
                    f"missing_{header.replace('-', '_')}",
                    f"{display_name} response header is missing.",
                    severity,
                    f"Final response from {final_url} did not include {header}.",
                    "missing_protection",
                )

        result["mixed_content"] = _inspect_page_html(
            final_url,
            headers.get("content-type", ""),
            headers.get("content-encoding", ""),
            scan.get("body", b""),
            scan.get("body_truncated", False),
        )
        mixed = result["mixed_content"]
        if mixed["resources"]:
            hosts = sorted({
                resource["hostname"] for resource in mixed["resources"]
                if resource.get("hostname")
            })
            add_finding(
                "mixed_content_detected",
                "HTTPS page references one or more HTTP resources.",
                "high",
                (
                    f"Found {mixed['resource_count']} insecure resource reference(s) "
                    f"to host(s): {', '.join(hosts)}."
                ),
                "confirmed_insecure_resource_reference",
            )
        if mixed["insecure_forms"]:
            add_finding(
                "insecure_form_action",
                "HTTPS page submits a form to an HTTP endpoint.",
                "high",
                "Observed HTTP form destination(s): "
                + ", ".join(sorted(set(mixed["insecure_forms"]))) + ".",
                "confirmed_insecure_form_configuration",
            )

        result["server"] = headers.get("server")
        result["powered_by"] = headers.get("x-powered-by")
        if result["server"]:
            add_finding(
                "server_header_exposed",
                "Server technology information is exposed.",
                "low",
                f"Server response header is present: {result['server']}.",
                "observed_information_exposure",
            )
        if result["powered_by"]:
            add_finding(
                "powered_by_header_exposed",
                "X-Powered-By information is exposed.",
                "low",
                f"X-Powered-By response header is present: {result['powered_by']}.",
                "observed_information_exposure",
            )

        result["cookies"] = _inspect_cookies(scan.get("set_cookie_headers", []))
        result["cookie_status"] = "checked"
        cookies = result["cookies"]
        missing_http_only = sorted({
            cookie["name"] for cookie in cookies if not cookie["http_only"]
        })
        missing_same_site = sorted({
            cookie["name"] for cookie in cookies if not cookie["same_site"]
        })
        insecure_same_site_none = sorted({
            cookie["name"]
            for cookie in cookies
            if cookie["same_site"]
            and cookie["same_site"].lower() == "none"
            and not cookie["secure"]
        })
        missing_secure = sorted({
            cookie["name"]
            for cookie in cookies
            if not cookie["secure"]
            and not (
                cookie["same_site"]
                and cookie["same_site"].lower() == "none"
            )
        })
        cookie_findings = (
            (
                "cookie_missing_httponly",
                "Cookie is missing the HttpOnly attribute.",
                "low",
                missing_http_only,
                "missing_cookie_protection",
                "were set without HttpOnly",
            ),
            (
                "cookie_missing_samesite",
                "Cookie is missing the SameSite attribute.",
                "low",
                missing_same_site,
                "missing_cookie_protection",
                "were set without SameSite",
            ),
            (
                "cookie_samesite_none_without_secure",
                "SameSite=None cookie is missing the Secure attribute.",
                "medium",
                insecure_same_site_none,
                "confirmed_insecure_cookie_configuration",
                "use SameSite=None without Secure",
            ),
            (
                "cookie_missing_secure",
                "Cookie is missing the Secure attribute.",
                "medium",
                missing_secure,
                "missing_cookie_protection",
                "were set without Secure",
            ),
        )
        for code, title, severity, names, classification, description in cookie_findings:
            if names:
                add_finding(
                    code,
                    title,
                    severity,
                    f"Cookie name(s) {', '.join(repr(name) for name in names)} {description}; cookie values are not recorded.",
                    classification,
                )

        if original_is_http:
            upgraded = any(
                urlparse(hop["from"]).scheme == "http"
                and urlparse(hop["to"]).scheme == "https"
                for hop in hops
            ) and final_is_https
            result["https_enforced"] = upgraded
            result["https_enforcement"] = {
                "status": "enforced" if upgraded else "not_enforced",
                "tested_url": requested_url,
                "final_url": final_url,
            }
            if not upgraded:
                add_finding(
                    "https_not_enforced",
                    "HTTP request was not upgraded to HTTPS.",
                    "medium",
                    f"Request to {requested_url} completed at {final_url} without an observed upgrade to HTTPS.",
                    "missing_transport_protection",
                )
        else:
            probe_url = _http_probe_url(requested_url)
            probe = _request_chain(probe_url)
            probe_hops = probe.get("redirects", [])
            probe_final = probe.get("final_url")
            upgraded = (
                probe["status"] == "completed"
                and any(
                    urlparse(hop["from"]).scheme == "http"
                    and urlparse(hop["to"]).scheme == "https"
                    for hop in probe_hops
                )
                and bool(probe_final)
                and urlparse(probe_final).scheme == "https"
            )
            if probe["status"] == "completed":
                result["https_enforced"] = upgraded
                result["https_enforcement"] = {
                    "status": "enforced" if upgraded else "not_enforced",
                    "tested_url": probe_url,
                    "final_url": probe_final,
                }
                if not upgraded:
                    add_finding(
                        "https_not_enforced",
                        "HTTP request was not upgraded to HTTPS.",
                        "medium",
                        f"HTTP probe completed at {probe_final} without an observed upgrade to HTTPS.",
                        "missing_transport_protection",
                    )
            elif probe["status"] in ("redirect_loop", "redirect_limit"):
                loop_detected = probe["status"] == "redirect_loop"
                result["https_enforcement"] = {
                    "status": probe["status"],
                    "tested_url": probe_url,
                    "final_url": probe_final,
                    "redirects": probe_hops,
                }
                code = "redirect_loop_detected" if loop_detected else "redirect_limit_reached"
                title = "A redirect loop was detected." if loop_detected else "HTTP probe exceeded the redirect limit."
                add_finding(
                    code,
                    title,
                    "medium",
                    (
                        f"The HTTP-to-HTTPS enforcement probe "
                        f"{'revisited ' + str(probe_final) if loop_detected else 'exceeded the redirect limit'}."
                    ),
                    "confirmed_configuration_issue",
                )
            else:
                result["https_enforcement"] = {
                    "status": "unavailable",
                    "tested_url": probe_url,
                    "error": probe.get("error"),
                }

        result["risk_score"] = _severity_risk(result["finding_details"])
    except socket.timeout:
        result.update(status="unavailable", error="Website request timed out.")
    except socket.gaierror:
        result.update(status="unavailable", error="Could not resolve website hostname.")
    except BlockedDestinationError as error:
        result.update(status="blocked", error=str(error))
    except (http.client.HTTPException, ssl.SSLError, OSError):
        result.update(status="unavailable", error="Could not connect to website.")
    except ValueError:
        result.update(status="unavailable", error="Website assessment failed.")

    return result

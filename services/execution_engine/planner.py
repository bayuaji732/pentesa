"""OWASP WSTG Test Planner & Applicability Engine.

Responsible for:
1. Seeding and updating the master WSTG v4.2 test catalog.
2. Initializing project-specific test matrices.
3. Analyzing attack surface inventory to determine test applicability.
4. Validating and enforcing WSTG test state transitions.
"""

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.discovery import Cookie, DiscoveredDomain, Endpoint, Technology
from database.models.finding import Finding
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from packages.common.exceptions import BadRequestException
from services.execution_engine.wstg_catalog_data import WSTG_CATALOG_ITEMS
from services.scope_engine.validator import parse_port_range


# Finite state transition rules for WSTG test cases
VALID_STATE_TRANSITIONS: Dict[str, Set[str]] = {
    "Not Started": {"Planned", "Not Applicable", "Not Executed"},
    "Planned": {"Running", "Not Applicable", "Not Started", "Blocked", "Not Executed"},
    "Running": {"Passed", "Failed", "Needs Manual Review", "Blocked", "Error", "Planned", "Not Executed"},
    "Needs Manual Review": {"Passed", "Failed", "Running"},
    "Blocked": {"Running", "Planned", "Not Applicable", "Not Executed"},
    "Error": {"Running", "Planned", "Not Applicable", "Not Executed"},
    "Passed": {"Failed", "Needs Manual Review", "Not Applicable", "Planned"},  # Manual override
    "Failed": {"Passed", "Needs Manual Review", "Not Applicable", "Planned"},  # Manual override
    "Not Applicable": {"Planned", "Not Started"},
    "Not Executed": {"Running", "Planned", "Not Applicable"},
}


def validate_status_transition(
    current_status: str,
    new_status: str,
    justification: Optional[str] = None
) -> None:
    """Validate that a WSTG test status transition obeys the lifecycle state machine.
    
    Raises:
        BadRequestException: If transition is invalid or lacks mandatory justification.
    """
    if current_status == new_status:
        return

    allowed_targets = VALID_STATE_TRANSITIONS.get(current_status, set())
    if new_status not in allowed_targets:
        raise BadRequestException(
            f"Invalid WSTG status transition from '{current_status}' to '{new_status}'."
        )

    # Transitioning to 'Not Applicable' requires an explicit justification
    if new_status == "Not Applicable" and (not justification or not justification.strip()):
        raise BadRequestException(
            "Marking a WSTG test as 'Not Applicable' requires an explicit justification."
        )

    # Overriding a terminal result ('Passed' or 'Failed') requires justification
    if current_status in {"Passed", "Failed"} and (not justification or not justification.strip()):
        raise BadRequestException(
            f"Overriding a confirmed '{current_status}' test status requires an explicit justification."
        )


async def seed_wstg_catalog(session: AsyncSession) -> int:
    """Seed or update the master WSTG v4.2 test catalog in the database.
    
    Returns:
        Number of catalog items populated or refreshed.
    """
    stmt = select(WSTGTestCatalog)
    result = await session.execute(stmt)
    existing_map = {item.id: item for item in result.scalars().all()}

    count = 0
    for raw in WSTG_CATALOG_ITEMS:
        item_id = raw["id"]
        if item_id in existing_map:
            # Update attributes if needed
            existing = existing_map[item_id]
            existing.category = raw["category"]
            existing.category_code = raw["category_code"]
            existing.name = raw["name"]
            existing.description = raw["description"]
            existing.automation_capability = raw["automation_capability"]
            existing.default_risk = raw["default_risk"]
            existing.cwe_id = raw.get("cwe_id")
            existing.owasp_category = raw.get("owasp_category")
            existing.required_tools = raw.get("required_tools", [])
            existing.requires_human_review = raw.get("requires_human_review", False)
            existing.endpoint_types = raw.get("endpoint_types", [])
        else:
            new_item = WSTGTestCatalog(
                id=item_id,
                category=raw["category"],
                category_code=raw["category_code"],
                name=raw["name"],
                description=raw["description"],
                automation_capability=raw["automation_capability"],
                default_risk=raw["default_risk"],
                cwe_id=raw.get("cwe_id"),
                owasp_category=raw.get("owasp_category"),
                required_tools=raw.get("required_tools", []),
                requires_human_review=raw.get("requires_human_review", False),
                endpoint_types=raw.get("endpoint_types", [])
            )
            session.add(new_item)
        count += 1

    await session.commit()
    return count


async def initialize_project_wstg_instances(
    session: AsyncSession,
    project_id: uuid.UUID
) -> int:
    """Initialize WSTG test case instances for a project from the master catalog.
    
    Creates instances for any catalog test that hasn't yet been instantiated.
    
    Returns:
        Number of new test instances created.
    """
    # Fetch all catalog items
    catalog_stmt = select(WSTGTestCatalog)
    cat_result = await session.execute(catalog_stmt)
    catalog_items = cat_result.scalars().all()

    if not catalog_items:
        # Seed catalog if empty
        await seed_wstg_catalog(session)
        cat_result = await session.execute(catalog_stmt)
        catalog_items = cat_result.scalars().all()

    # Fetch existing instances for this project
    inst_stmt = select(WSTGTestInstance.wstg_id).where(WSTGTestInstance.project_id == project_id)
    inst_result = await session.execute(inst_stmt)
    existing_ids = set(inst_result.scalars().all())

    created = 0
    now = datetime.now(timezone.utc)
    for cat in catalog_items:
        if cat.id not in existing_ids:
            instance = WSTGTestInstance(
                project_id=project_id,
                wstg_id=cat.id,
                status="Not Started",
                notes=None,
                justification=None,
                applicable_endpoints_count=0,
                updated_at=now
            )
            session.add(instance)
            created += 1

    if created > 0:
        await session.commit()

    return created


_FILE_TOKENS = {
    "file", "files", "upload", "uploaded", "attachment", "attachments",
    "avatar", "photo", "image", "img", "document", "doc", "resume",
    "import", "page", "path", "include", "template", "dir", "folder",
    "download", "filepath", "filename",
}
_UPLOAD_TOKENS = {
    "file", "files", "upload", "uploaded", "attachment", "attachments",
    "avatar", "photo", "image", "img", "document", "doc", "resume", "import",
}
_URL_TOKENS = {
    "url", "uri", "webhook", "callback", "target", "dest", "destination",
    "fetch", "feed", "proxy",
}
_REDIRECT_EXACT = {
    "next", "redirect", "redirect_uri", "redirect_url", "return_to",
    "return_url", "returnto", "continue", "goto", "dest", "destination",
}
_STYLE_TOKENS = {
    "css", "style", "styles", "theme", "color", "bgcolor",
    "font", "background", "stylesheet",
}
_TOKEN_TOKENS = {
    "token", "session", "sid", "phpsessid", "jsessionid", "auth",
    "jwt", "access_token", "id_token", "api_key", "apikey", "secret",
    "hash", "sig", "signature", "csrftoken",
}
_MAIL_TOKENS = {
    "email", "mail", "smtp", "imap", "cc", "bcc", "sender", "subject", "mailer",
}
_XPATH_TOKENS = {"xml", "xpath", "xslt", "xsl", "soap", "saml"}
_ID_TOKENS = {
    "id", "uid", "uuid", "user", "userid", "account", "accountid",
    "order", "orderid", "item", "itemid", "basket", "profile",
    "invoice", "record", "recipient",
}
_COOKIE_IMPLIED_TECHS = {
    "Java (Servlet/Spring)", "Express / Node.js", "Django", "Laravel",
}
_DYNAMIC_INCLUDE_TECHS = {"PHP", "Java (Servlet/Spring)", "ASP.NET"}


def _tokenize_param_name(name: str) -> Set[str]:
    """Split camelCase, snake_case, and kebab-case parameter names into lowercase tokens."""
    if not name:
        return set()
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name))
    tokens = {tok for tok in re.split(r"[^a-z0-9]+", camel_split.lower()) if tok}
    return tokens


def _extract_param_info(endpoint: Endpoint) -> Dict[str, Any]:
    """Safely inspect endpoint parameter_schema across list-of-dicts, list-of-strings, and flat dict shapes."""
    schema = endpoint.parameter_schema
    info: Dict[str, Any] = {
        "has_params": False,
        "has_query_or_path": False,
        "has_json": False,
        "has_file_input": False,
        "has_password_input": False,
        "has_hidden_input": False,
        "has_file_param": False,
        "has_upload_param": False,
        "has_url_param": False,
        "has_redirect_param": False,
        "has_style_param": False,
        "has_token_param": False,
        "has_mail_param": False,
        "has_xpath_param": False,
        "has_id_param": False,
        "param_names": [],
    }
    if not isinstance(schema, dict) or not schema:
        return info

    def _inspect_param(raw_name: str, raw_type: str, loc: str) -> None:
        p_name = (raw_name or "").strip()
        p_type = (raw_type or "").strip().lower()
        if not p_name:
            return
        info["param_names"].append(p_name)
        if loc in ("query", "body", "json", "path"):
            info["has_params"] = True
        if loc in ("query", "path"):
            info["has_query_or_path"] = True
        if loc == "json":
            info["has_json"] = True
        if p_type == "file":
            info["has_file_input"] = True
        elif p_type == "password":
            info["has_password_input"] = True
        elif p_type == "hidden":
            info["has_hidden_input"] = True

        low_name = p_name.lower()
        tokens = _tokenize_param_name(p_name)
        if tokens & _FILE_TOKENS:
            info["has_file_param"] = True
        if tokens & _UPLOAD_TOKENS:
            info["has_upload_param"] = True
        if tokens & _URL_TOKENS or "url" in tokens:
            info["has_url_param"] = True
        if low_name in _REDIRECT_EXACT or "redirect" in tokens or "returnto" in tokens:
            info["has_redirect_param"] = True
        if tokens & _STYLE_TOKENS:
            info["has_style_param"] = True
        if tokens & _TOKEN_TOKENS:
            info["has_token_param"] = True
        if tokens & _MAIL_TOKENS:
            info["has_mail_param"] = True
        if tokens & _XPATH_TOKENS:
            info["has_xpath_param"] = True
        if (tokens & _ID_TOKENS) or low_name.endswith("_id") or low_name == "id":
            info["has_id_param"] = True

    container_keys = ("query", "body", "json", "path", "headers")
    has_container_shape = any(isinstance(schema.get(k), list) for k in container_keys)

    if has_container_shape:
        for loc in container_keys:
            items = schema.get(loc)
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict):
                    p_name = str(item.get("name") or item.get("key") or "")
                    p_type = str(item.get("type") or "")
                    eff_loc = str(item.get("location") or loc).lower()
                else:
                    p_name = str(item)
                    p_type = ""
                    eff_loc = loc
                _inspect_param(p_name, p_type, eff_loc)
    else:
        for k, v in schema.items():
            if k in container_keys:
                continue
            p_type = str(v) if isinstance(v, str) else (
                str(v.get("type", "")) if isinstance(v, dict) else ""
            )
            _inspect_param(str(k), p_type, "body")

    return info


def _extract_hostname(candidate: str) -> str:
    """Normalize URL, pattern, or wildcard domain string into bare lowercase hostname."""
    val = (candidate or "").strip().lower()
    if not val:
        return ""
    if "://" in val:
        val = urlparse(val).hostname or ""
    else:
        val = val.split("/")[0].lstrip("*.")
        if ":" in val and not val.startswith("["):
            val = val.split(":", 1)[0]
    return val.strip().rstrip(".")


def _is_public_fqdn(hostname: str) -> bool:
    """Return True only when hostname looks like a routable multi-label public domain."""
    h = _extract_hostname(hostname)
    if not h or h in {"localhost", "host.docker.internal", "localhost.localdomain"}:
        return False
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    if "." not in h or h.endswith((".local", ".internal", ".localhost")):
        return False
    return True


def _detect_has_https(
    project: Optional[Project],
    rules: List[ScopeRule],
    technologies: List[Technology],
    fqdns: Set[str],
) -> bool:
    """Determine whether the project target exposes HTTPS/TLS or runs plaintext HTTP only."""
    tech_urls = [
        (t.detected_on_url or "").strip().lower()
        for t in technologies
        if getattr(t, "detected_on_url", None)
    ]
    if tech_urls:
        if any(u.startswith("https://") for u in tech_urls):
            return True
        if all(u.startswith("http://") for u in tech_urls):
            return False

    in_scope_rules = [r for r in rules if r.target_type == "IN_SCOPE"]
    explicit_schemes: Set[str] = set()
    raw_targets = list(getattr(project, "target_domains", None) or []) + [
        r.pattern for r in in_scope_rules if r.pattern
    ]
    for target in raw_targets:
        low = (target or "").strip().lower()
        if low.startswith("https://"):
            explicit_schemes.add("https")
        elif low.startswith("http://"):
            explicit_schemes.add("http")
    if explicit_schemes:
        return "https" in explicit_schemes

    all_ports: Set[int] = set()
    all_protos: Set[str] = set()
    for r in in_scope_rules:
        if r.port_range:
            all_ports.update(parse_port_range(r.port_range))
        if r.protocol:
            for p in re.split(r"[,\s]+", r.protocol.lower()):
                if p:
                    all_protos.add(p)

    if all_ports:
        return any(p in (443, 8443, 4433) for p in all_ports)
    if all_protos:
        return "https" in all_protos

    if fqdns and not any(_is_public_fqdn(h) for h in fqdns):
        return False

    return True


async def sync_wstg_instance_for_finding(
    session: AsyncSession,
    project_id: uuid.UUID,
    wstg_id: Optional[str],
) -> None:
    """Keep WSTGTestInstance status synchronized with empirical Findings for (project_id, wstg_id)."""
    if not wstg_id:
        return

    inst_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == project_id,
        WSTGTestInstance.wstg_id == wstg_id,
    )
    instance = (await session.execute(inst_stmt)).scalar_one_or_none()
    if not instance:
        return

    findings_stmt = select(Finding.status).where(
        Finding.project_id == project_id,
        Finding.wstg_id == wstg_id,
    )
    statuses = list((await session.execute(findings_stmt)).scalars().all())

    active_count = sum(
        1 for st in statuses if st not in {"False Positive", "Remediated", "Retested"}
    )
    remediated_count = sum(1 for st in statuses if st == "Remediated")

    changed = False
    now = datetime.now(timezone.utc)
    if active_count > 0:
        if instance.status != "Failed":
            instance.status = "Failed"
            instance.applicable_endpoints_count = max(instance.applicable_endpoints_count, 1)
            instance.updated_at = now
            changed = True
    elif instance.status == "Failed":
        instance.status = "Passed" if remediated_count > 0 else "Planned"
        instance.updated_at = now
        changed = True

    if changed:
        await session.commit()


async def recalculate_project_test_plan(
    session: AsyncSession,
    project_id: uuid.UUID
) -> Dict[str, Any]:
    """Analyze project attack surface and update WSTG test applicability.

    Determines empirically whether each WSTG v4.2 test should transition to
    'Planned', 'Not Applicable', or sync with active/remediated Findings based on
    discovered domains, endpoints, schemas, HTTP vs HTTPS transport, cookies, and
    detected technologies.

    Returns:
        Summary dict of planned, not applicable, failed, and analyzed surface totals.
    """
    # Ensure instances are initialized
    await initialize_project_wstg_instances(session, project_id)

    # 1. Fetch project metadata & complete attack surface
    project = (await session.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    rules = list(
        (await session.execute(select(ScopeRule).where(ScopeRule.project_id == project_id))).scalars().all()
    )
    domains = list(
        (await session.execute(select(DiscoveredDomain).where(DiscoveredDomain.project_id == project_id))).scalars().all()
    )
    endpoints = list(
        (await session.execute(select(Endpoint).where(Endpoint.project_id == project_id))).scalars().all()
    )
    cookies = list(
        (await session.execute(select(Cookie).where(Cookie.project_id == project_id))).scalars().all()
    )
    technologies = list(
        (await session.execute(select(Technology).where(Technology.project_id == project_id))).scalars().all()
    )
    finding_rows = (
        await session.execute(
            select(Finding.wstg_id, Finding.status).where(
                Finding.project_id == project_id,
                Finding.wstg_id.is_not(None),
            )
        )
    ).all()

    active_findings_by_wstg: Dict[str, int] = {}
    remediated_findings_by_wstg: Dict[str, int] = {}
    for f_wstg_id, f_status in finding_rows:
        if not f_wstg_id:
            continue
        if f_status == "Remediated":
            remediated_findings_by_wstg[f_wstg_id] = remediated_findings_by_wstg.get(f_wstg_id, 0) + 1
        elif f_status not in {"False Positive", "Retested"}:
            active_findings_by_wstg[f_wstg_id] = active_findings_by_wstg.get(f_wstg_id, 0) + 1

    # Host / transport context
    all_fqdns: Set[str] = {
        _extract_hostname(d.fqdn) for d in domains if getattr(d, "fqdn", None)
    } | {
        _extract_hostname(e.fqdn) for e in endpoints if getattr(e, "fqdn", None)
    } | {
        _extract_hostname(t) for t in (getattr(project, "target_domains", None) or [])
    }
    all_fqdns.discard("")

    public_fqdns = {h for h in all_fqdns if _is_public_fqdn(h)}
    has_public_fqdn = len(public_fqdns) > 0
    has_https = _detect_has_https(project, rules, technologies, all_fqdns)

    tech_names = {t.name for t in technologies if t.name}
    tech_categories = {t.category for t in technologies if t.category}
    effective_has_cookies = len(cookies) > 0 or bool(tech_names & _COOKIE_IMPLIED_TECHS)
    cookie_evidence_count = len(cookies) if cookies else (
        1 if (tech_names & _COOKIE_IMPLIED_TECHS) else 0
    )
    has_frontend_framework = "FRONTEND_FRAMEWORK" in tech_categories

    # 2. Index every endpoint once with safe parameter inspection
    has_endpoints = len(endpoints) > 0
    parameterized_endpoints: List[Endpoint] = []
    query_or_path_endpoints: List[Endpoint] = []
    mutation_endpoints: List[Endpoint] = []
    form_endpoints: List[Endpoint] = []
    api_endpoints: List[Endpoint] = []
    api_mutation_endpoints: List[Endpoint] = []
    api_upload_endpoints: List[Endpoint] = []
    api_id_or_param_endpoints: List[Endpoint] = []
    xml_endpoints: List[Endpoint] = []
    web_endpoints: List[Endpoint] = []
    js_or_web_endpoints: List[Endpoint] = []
    static_or_file_endpoints: List[Endpoint] = []
    metafile_endpoints: List[Endpoint] = []
    login_endpoints: List[Endpoint] = []
    register_endpoints: List[Endpoint] = []
    reset_pwd_endpoints: List[Endpoint] = []
    logout_endpoints: List[Endpoint] = []
    admin_endpoints: List[Endpoint] = []
    provisioning_endpoints: List[Endpoint] = []
    auth_protected_endpoints: List[Endpoint] = []
    profile_endpoints: List[Endpoint] = []
    rbac_endpoints: List[Endpoint] = []
    auth_endpoints: List[Endpoint] = []
    upload_endpoints: List[Endpoint] = []
    websocket_endpoints: List[Endpoint] = []
    workflow_endpoints: List[Endpoint] = []
    cloud_storage_endpoints: List[Endpoint] = []
    webhook_or_url_endpoints: List[Endpoint] = []
    mobile_endpoints: List[Endpoint] = []
    mail_contact_endpoints: List[Endpoint] = []
    redirect_param_endpoints: List[Endpoint] = []
    style_param_endpoints: List[Endpoint] = []
    token_param_endpoints: List[Endpoint] = []
    xpath_param_endpoints: List[Endpoint] = []
    file_param_or_include_endpoints: List[Endpoint] = []
    idor_endpoints: List[Endpoint] = []
    swf_endpoints: List[Endpoint] = []
    native_c_endpoints: List[Endpoint] = []

    for e in endpoints:
        path_low = (e.url_path or "/").lower()
        fqdn_low = (e.fqdn or "").lower()
        method_upper = (e.http_method or "GET").upper()
        ct_low = (e.content_type or "").lower()
        src_upper = (e.discovery_source or "").upper()
        pinfo = _extract_param_info(e)

        is_sitemap = path_low.endswith("/sitemap.xml") or path_low == "sitemap.xml"
        is_metafile = (
            src_upper in {"ROBOTS_TXT", "SITEMAP"}
            or path_low.endswith(("/robots.txt", "/sitemap.xml", "/security.txt", "/humans.txt"))
        )
        if is_metafile:
            metafile_endpoints.append(e)

        if pinfo["has_params"]:
            parameterized_endpoints.append(e)
        if pinfo["has_query_or_path"]:
            query_or_path_endpoints.append(e)
        if method_upper in {"POST", "PUT", "PATCH", "DELETE"}:
            mutation_endpoints.append(e)

        is_xml_ep = (not is_sitemap) and (
            "xml" in ct_low
            or "soap" in ct_low
            or "saml" in ct_low
            or pinfo["has_xpath_param"]
            or any(k in path_low for k in ("/xml", "soap", "saml", "wsdl"))
        )
        if is_xml_ep:
            xml_endpoints.append(e)
        if pinfo["has_xpath_param"] or "xpath" in path_low:
            xpath_param_endpoints.append(e)

        is_api_ep = (
            path_low.startswith("/api")
            or "/api/" in path_low
            or path_low.startswith("/rest/")
            or "/rest/" in path_low
            or path_low.startswith("/graphql")
            or path_low.endswith((".json", "/swagger.json", "/openapi.json"))
            or src_upper == "OPENAPI"
            or "json" in ct_low
            or "graphql" in ct_low
            or pinfo["has_json"]
        )
        if is_api_ep:
            api_endpoints.append(e)
            if pinfo["has_params"] or pinfo["has_id_param"] or "{" in path_low:
                api_id_or_param_endpoints.append(e)
            if method_upper in {"POST", "PUT", "PATCH", "DELETE"} or any(
                k in path_low for k in ("/transfer", "/checkout", "/order", "/payment", "/basket", "/cart")
            ):
                api_mutation_endpoints.append(e)

        is_js_asset = src_upper == "JS_ANALYSIS" or path_low.endswith((".js", ".mjs"))
        is_non_html_asset = path_low.endswith(
            (".xml", ".txt", ".json", ".css", ".js", ".mjs", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2")
        )
        is_web_ep = (
            "html" in ct_low
            or src_upper == "FORM"
            or "x-www-form-urlencoded" in ct_low
            or "multipart" in ct_low
            or path_low.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jspx", "/"))
            or (not is_api_ep and not is_xml_ep and not is_non_html_asset)
        )
        if is_web_ep:
            web_endpoints.append(e)
        if is_web_ep or is_js_asset or has_frontend_framework:
            js_or_web_endpoints.append(e)

        is_form_ep = (
            src_upper == "FORM"
            or "x-www-form-urlencoded" in ct_low
            or "multipart" in ct_low
            or (method_upper == "POST" and not is_api_ep and "json" not in ct_low)
        )
        if is_form_ep:
            form_endpoints.append(e)

        is_static_ep = (
            path_low.endswith(
                (".php", ".asp", ".aspx", ".jsp", ".jspx", ".html", ".htm", ".js", ".css", ".txt", ".xml", ".env", ".git", ".bak", ".old", ".config", ".yml", ".yaml", ".ini")
            )
            or any(k in path_low for k in ("/static/", "/assets/", "/public/", "/uploads/", "/files/", "/config"))
        )
        if is_static_ep:
            static_or_file_endpoints.append(e)

        is_register_ep = any(
            k in path_low for k in ("register", "signup", "sign-up", "create-account", "create_user")
        ) or (
            path_low.rstrip("/").endswith(("/users", "/user"))
            and method_upper == "POST"
        )
        if is_register_ep:
            register_endpoints.append(e)

        is_reset_ep = any(
            k in path_low
            for k in (
                "reset-password", "reset_password", "forgot-password", "forgot_password",
                "forgot", "recover", "change-password", "change_password", "passwd",
                "security-question", "security_question",
            )
        )
        if is_reset_ep:
            reset_pwd_endpoints.append(e)

        is_logout_ep = any(k in path_low for k in ("logout", "signout", "sign-out", "logoff"))
        if is_logout_ep:
            logout_endpoints.append(e)

        is_login_ep = (
            any(k in path_low for k in ("/login", "login.", "/signin", "signin", "/authenticate", "/auth/token", "/oauth/token"))
            or (pinfo["has_password_input"] and not is_register_ep and not is_reset_ep)
        )
        if is_login_ep:
            login_endpoints.append(e)

        is_admin_ep = any(
            k in path_low
            for k in (
                "/admin", "administrator", "phpmyadmin", "/actuator", "/manage",
                "/management", "/console", "/setup", "setup.", "/phpinfo", "phpinfo",
                "/debug", "/internal", "/panel", "/staff", "/sysadmin",
            )
        )
        if is_admin_ep:
            admin_endpoints.append(e)

        if any(k in path_low for k in ("/provision", "/invite", "/onboarding", "/setup", "setup.", "/create-user", "/create_user", "/admin")):
            provisioning_endpoints.append(e)

        is_auth_ep = (
            e.auth_required
            or is_login_ep
            or is_register_ep
            or is_reset_ep
            or any(k in path_low for k in ("/auth", "/token", "/session", "/oauth", "/sso"))
        )
        if is_auth_ep:
            auth_endpoints.append(e)

        if e.auth_required or any(
            k in path_low
            for k in (
                "/profile", "/account", "/dashboard", "/admin", "/settings",
                "/users", "/user/", "/orders", "/transfer", "/bank/",
                "/vulnerabilities/", "/whoami", "/basket", "/checkout",
                "/internal", "/debug", "/setup",
            )
        ):
            auth_protected_endpoints.append(e)

        if any(k in path_low for k in ("/profile", "/account", "/settings", "/me", "/whoami", "/preferences", "/users/", "/user/")):
            profile_endpoints.append(e)

        if any(k in path_low for k in ("/role", "/roles", "/permission", "/permissions", "/admin", "/users", "/rbac", "/acl", "/group")):
            rbac_endpoints.append(e)

        is_upload_ep = (
            "multipart" in ct_low
            or pinfo["has_file_input"]
            or pinfo["has_upload_param"]
            or any(k in path_low for k in ("/upload", "/uploads", "upload.", "/import", "/attachment", "/attachments", "/avatar"))
        )
        if is_upload_ep:
            upload_endpoints.append(e)
            if is_api_ep:
                api_upload_endpoints.append(e)

        if any(k in path_low for k in ("/ws", "/wss", "websocket", "socket.io", "engine.io", "sockjs", "signalr")):
            websocket_endpoints.append(e)

        if any(
            k in path_low
            for k in (
                "/transfer", "/checkout", "/cart", "/basket", "/order", "/orders",
                "/payment", "/payments", "/pay", "/wizard", "/step", "/approve",
                "/approval", "/verify", "/confirm", "/transaction", "/do_transfer",
            )
        ):
            workflow_endpoints.append(e)

        if any(
            k in path_low or k in fqdn_low
            for k in ("amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "/s3", "/bucket", "/blob", "/cloud-storage")
        ):
            cloud_storage_endpoints.append(e)

        if pinfo["has_url_param"] or any(k in path_low for k in ("/webhook", "/webhooks", "/callback", "/hook", "/notify", "/proxy", "/fetch")):
            webhook_or_url_endpoints.append(e)

        if any(k in path_low for k in ("/mobile", "/app/v", "/ios", "/android")):
            mobile_endpoints.append(e)

        if pinfo["has_mail_param"] or any(
            k in path_low for k in ("/contact", "/feedback", "/support", "/mail", "/smtp", "/newsletter", "/complaint")
        ):
            mail_contact_endpoints.append(e)

        if pinfo["has_redirect_param"] or any(k in path_low for k in ("/redirect", "/oauth", "/sso")):
            redirect_param_endpoints.append(e)

        if pinfo["has_style_param"] or "style" in path_low or "theme" in path_low:
            style_param_endpoints.append(e)

        if pinfo["has_token_param"]:
            token_param_endpoints.append(e)

        if pinfo["has_file_param"] or any(
            k in path_low for k in ("/fi", "/include", "/download", "/view", "/file", "/readfile")
        ):
            file_param_or_include_endpoints.append(e)

        if pinfo["has_id_param"] or "{" in path_low or is_api_ep and pinfo["has_params"]:
            idor_endpoints.append(e)

        if path_low.endswith(".swf"):
            swf_endpoints.append(e)

        if any(path_low.endswith(ext) for ext in (".cgi", ".dll", ".exe", ".so")):
            native_c_endpoints.append(e)

    has_dynamic_include_runtime = bool(tech_names & _DYNAMIC_INCLUDE_TECHS) or any(
        ".php" in (e.url_path or "").lower() or ".jsp" in (e.url_path or "").lower()
        for e in endpoints
    )

    # Fetch all project instances with their catalog metadata
    inst_stmt = (
        select(WSTGTestInstance, WSTGTestCatalog)
        .join(WSTGTestCatalog, WSTGTestInstance.wstg_id == WSTGTestCatalog.id)
        .where(WSTGTestInstance.project_id == project_id)
    )
    instances = (await session.execute(inst_stmt)).all()

    now = datetime.now(timezone.utc)

    # Pre-crawl baseline tests (used only when zero endpoints have been discovered yet)
    _PRE_CRAWL_UNIVERSAL = {
        "WSTG-INFO-01", "WSTG-INFO-02", "WSTG-INFO-03", "WSTG-INFO-04",
        "WSTG-INFO-06", "WSTG-INFO-08", "WSTG-INFO-09",
        "WSTG-CONF-01", "WSTG-CONF-02", "WSTG-CONF-04", "WSTG-CONF-06",
        "WSTG-CONF-07", "WSTG-CONF-08", "WSTG-CONF-10",
        "WSTG-ERRH-01", "WSTG-ERRH-02",
        "WSTG-CRYP-01", "WSTG-CRYP-03", "WSTG-CRYP-04",
        "WSTG-BUSL-07", "WSTG-CLNT-09",
    }

    for instance, catalog in instances:
        cid = catalog.id

        # Synchronize first with empirically recorded Findings (non-False Positive)
        if active_findings_by_wstg.get(cid, 0) > 0:
            if instance.status != "Failed":
                instance.status = "Failed"
                instance.applicable_endpoints_count = max(instance.applicable_endpoints_count, 1)
                instance.updated_at = now
            continue
        if instance.status == "Failed" and remediated_findings_by_wstg.get(cid, 0) > 0:
            instance.status = "Passed"
            instance.updated_at = now
            continue

        # Respect active or manually resolved states
        if instance.status in {"Running", "Passed", "Failed", "Needs Manual Review"}:
            continue

        applicable_count = 0
        is_applicable = False
        is_explicit_na = False
        na_reason = ""

        # Pre-crawl target without endpoints yet
        if not has_endpoints:
            if cid == "WSTG-CLNT-08":
                is_explicit_na = True
                na_reason = "No Adobe Flash or ActionScript (.swf) assets detected in discovered attack surface."
            elif cid in {"WSTG-CONF-07", "WSTG-CRYP-01", "WSTG-APIT-07"} and not has_https:
                is_explicit_na = True
                na_reason = "Target operates over plaintext HTTP only; HTTPS/TLS listener not configured."
            elif cid in {"WSTG-INFO-01", "WSTG-CONF-10"} and not has_public_fqdn:
                is_explicit_na = True
                na_reason = "Target uses IP, loopback, or internal single-label hostname; public DNS/OSINT check is not applicable."
            elif cid in _PRE_CRAWL_UNIVERSAL:
                is_applicable = True
                applicable_count = 1
        else:
            ep_total = len(endpoints)
            dom_total = max(len(domains), len(all_fqdns), 1)

            # -----------------------------------------------------------------
            # Exact per-test applicability across all 106 OWASP WSTG v4.2 rules
            # -----------------------------------------------------------------
            if cid == "WSTG-CLNT-08":
                if swf_endpoints:
                    is_applicable, applicable_count = True, len(swf_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No Adobe Flash or ActionScript (.swf) assets detected in discovered attack surface."

            elif cid in {"WSTG-CONF-07", "WSTG-CRYP-01"}:
                if has_https:
                    is_applicable, applicable_count = True, (ep_total if cid == "WSTG-CONF-07" else dom_total)
                else:
                    is_explicit_na = True
                    na_reason = "Target operates strictly over plaintext HTTP (no HTTPS/TLS listener detected)."

            elif cid == "WSTG-INFO-01":
                if has_public_fqdn:
                    is_applicable, applicable_count = True, len(public_fqdns)
                else:
                    is_explicit_na = True
                    na_reason = "Target resolves only to loopback, IP, or private/container hostnames; public search-engine OSINT does not apply."

            elif cid == "WSTG-CONF-10":
                if has_public_fqdn:
                    is_applicable, applicable_count = True, len(public_fqdns)
                else:
                    is_explicit_na = True
                    na_reason = "Target uses loopback, IP address, or single-label hostname; DNS subdomain takeover does not apply."

            elif cid in {"WSTG-INFO-02", "WSTG-INFO-04", "WSTG-INFO-08", "WSTG-INFO-09", "WSTG-CONF-01", "WSTG-CONF-04", "WSTG-CONF-08", "WSTG-INPV-15"}:
                is_applicable, applicable_count = True, dom_total

            elif cid == "WSTG-INFO-03":
                is_applicable = True
                applicable_count = len(metafile_endpoints) if metafile_endpoints else dom_total

            elif cid in {"WSTG-INFO-06", "WSTG-CONF-02", "WSTG-ERRH-01", "WSTG-ERRH-02", "WSTG-INPV-03", "WSTG-BUSL-07"}:
                is_applicable, applicable_count = True, ep_total

            elif cid in {"WSTG-CONF-06", "WSTG-CLNT-07", "WSTG-INFO-10"}:
                is_applicable = True
                applicable_count = len(api_endpoints) if api_endpoints else ep_total

            elif cid == "WSTG-CRYP-03":
                is_applicable = True
                sensitive = auth_endpoints or auth_protected_endpoints
                applicable_count = len(sensitive) if sensitive else ep_total

            elif cid == "WSTG-INFO-05":
                if js_or_web_endpoints:
                    is_applicable, applicable_count = True, len(js_or_web_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "Only machine-to-machine API endpoints detected; no client HTML/script pages to inspect."

            elif cid == "WSTG-INFO-07":
                combined = list({e.id: e for e in (workflow_endpoints + form_endpoints)}.values())
                if combined:
                    is_applicable, applicable_count = True, len(combined)
                else:
                    is_explicit_na = True
                    na_reason = "No multi-step execution workflows or HTML forms discovered in attack surface."

            elif cid == "WSTG-CONF-03":
                if static_or_file_endpoints:
                    is_applicable, applicable_count = True, len(static_or_file_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No static file handlers, server-side script extensions, or config file paths identified."

            elif cid == "WSTG-CONF-05":
                if admin_endpoints:
                    is_applicable, applicable_count = True, len(admin_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No administrative interfaces, management panels, or debug consoles discovered."

            elif cid == "WSTG-CONF-09":
                dir_candidates = list({e.id: e for e in (upload_endpoints + static_or_file_endpoints)}.values())
                if dir_candidates:
                    is_applicable, applicable_count = True, len(dir_candidates)
                else:
                    is_explicit_na = True
                    na_reason = "No upload directories or static asset paths detected for permission/indexing audit."

            elif cid == "WSTG-CONF-11":
                if cloud_storage_endpoints:
                    is_applicable, applicable_count = True, len(cloud_storage_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No AWS S3, GCP Cloud Storage, or Azure Blob endpoints or asset URLs detected."

            # Identity Management
            elif cid == "WSTG-IDNT-01":
                ident_eps = list({e.id: e for e in (rbac_endpoints + auth_endpoints)}.values())
                if ident_eps:
                    is_applicable, applicable_count = True, len(ident_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No authentication, role definition, or RBAC endpoints identified."

            elif cid in {"WSTG-IDNT-02", "WSTG-IDNT-05"}:
                if register_endpoints:
                    is_applicable, applicable_count = True, len(register_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No user self-registration or account creation endpoints discovered."

            elif cid == "WSTG-IDNT-03":
                if provisioning_endpoints:
                    is_applicable, applicable_count = True, len(provisioning_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No account provisioning, invitation, or administrative user setup routes discovered."

            elif cid == "WSTG-IDNT-04":
                enum_eps = list({e.id: e for e in (login_endpoints + reset_pwd_endpoints)}.values())
                if enum_eps:
                    is_applicable, applicable_count = True, len(enum_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No login or password-reset endpoints discovered for account enumeration."

            # Authentication Testing
            elif cid == "WSTG-ATHN-01":
                if auth_endpoints:
                    is_applicable, applicable_count = True, len(auth_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No credential submission or authentication endpoints identified."

            elif cid == "WSTG-ATHN-02":
                creds_eps = list({e.id: e for e in (login_endpoints + admin_endpoints)}.values())
                if creds_eps:
                    is_applicable, applicable_count = True, len(creds_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No login portals or administrative consoles discovered for default credential checks."

            elif cid in {"WSTG-ATHN-03", "WSTG-ATHN-05"}:
                if login_endpoints:
                    is_applicable, applicable_count = True, len(login_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No login form or authentication challenge endpoints discovered."

            elif cid in {"WSTG-ATHN-04", "WSTG-ATHZ-02"}:
                prot = list({e.id: e for e in (auth_protected_endpoints + admin_endpoints)}.values())
                if prot:
                    is_applicable, applicable_count = True, len(prot)
                else:
                    is_explicit_na = True
                    na_reason = "No protected or role-restricted endpoints discovered in attack surface."

            elif cid == "WSTG-ATHN-06":
                auth_web = [e for e in auth_protected_endpoints if e in web_endpoints or "json" not in (e.content_type or "").lower()]
                if auth_web:
                    is_applicable, applicable_count = True, len(auth_web)
                else:
                    is_explicit_na = True
                    na_reason = "No authenticated browser/HTML pages identified for cache-control review."

            elif cid == "WSTG-ATHN-07":
                pwd_eps = list({e.id: e for e in (register_endpoints + reset_pwd_endpoints)}.values())
                if pwd_eps:
                    is_applicable, applicable_count = True, len(pwd_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No registration, password-change, or password-reset endpoints discovered."

            elif cid in {"WSTG-ATHN-08", "WSTG-ATHN-09"}:
                if reset_pwd_endpoints:
                    is_applicable, applicable_count = True, len(reset_pwd_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No password reset, forgot-password, or security-question endpoints discovered."

            elif cid == "WSTG-ATHN-10":
                alt_eps = api_endpoints if auth_endpoints else []
                combined_alt = list({e.id: e for e in (alt_eps + mobile_endpoints)}.values())
                if combined_alt:
                    is_applicable, applicable_count = True, len(combined_alt)
                else:
                    is_explicit_na = True
                    na_reason = "No alternative API or mobile authentication channels discovered alongside primary auth."

            # Authorization Testing
            elif cid == "WSTG-ATHZ-01":
                fi_eps = list({e.id: e for e in (file_param_or_include_endpoints + query_or_path_endpoints)}.values())
                if fi_eps:
                    is_applicable, applicable_count = True, len(fi_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No URL path/query arguments or file-include parameters identified for traversal testing."

            elif cid == "WSTG-ATHZ-03":
                priv_eps = list({e.id: e for e in (profile_endpoints + rbac_endpoints + admin_endpoints)}.values())
                if priv_eps:
                    is_applicable, applicable_count = True, len(priv_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No user profile, role assignment, or privilege management endpoints discovered."

            elif cid == "WSTG-ATHZ-04":
                if idor_endpoints:
                    is_applicable, applicable_count = True, len(idor_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No object identifiers or tenant-scoped resource endpoints detected for IDOR testing."

            # Session Management
            elif cid in {"WSTG-SESS-01", "WSTG-SESS-09"}:
                if auth_endpoints or effective_has_cookies:
                    is_applicable = True
                    applicable_count = len(auth_endpoints) if auth_endpoints else cookie_evidence_count
                else:
                    is_explicit_na = True
                    na_reason = "No authentication mechanisms or session cookies observed."

            elif cid == "WSTG-SESS-02":
                if effective_has_cookies:
                    is_applicable, applicable_count = True, cookie_evidence_count
                else:
                    is_explicit_na = True
                    na_reason = "No HTTP Set-Cookie headers or session cookies observed during discovery."

            elif cid == "WSTG-SESS-03":
                if login_endpoints:
                    is_applicable, applicable_count = True, len(login_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No interactive login endpoint discovered for session fixation testing."

            elif cid == "WSTG-SESS-04":
                if token_param_endpoints or query_or_path_endpoints or effective_has_cookies or auth_endpoints:
                    is_applicable = True
                    applicable_count = len(token_param_endpoints) or len(query_or_path_endpoints) or len(auth_endpoints) or cookie_evidence_count
                else:
                    is_explicit_na = True
                    na_reason = "No URL parameters, session cookies, or token-bearing requests identified."

            elif cid == "WSTG-SESS-05":
                csrf_eps = list({e.id: e for e in (form_endpoints + mutation_endpoints)}.values())
                if csrf_eps:
                    is_applicable, applicable_count = True, len(csrf_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No HTML forms or state-changing (POST/PUT/PATCH/DELETE) endpoints discovered."

            elif cid == "WSTG-SESS-06":
                if logout_endpoints:
                    is_applicable, applicable_count = True, len(logout_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No accessible logout endpoint discovered (excluded from scope or stateless session flow)."

            elif cid == "WSTG-SESS-07":
                if auth_protected_endpoints or (auth_endpoints and effective_has_cookies):
                    is_applicable = True
                    applicable_count = len(auth_protected_endpoints) or len(auth_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No authenticated sessions or protected state discovered for timeout verification."

            elif cid == "WSTG-SESS-08":
                if auth_endpoints and (effective_has_cookies or rbac_endpoints or len(auth_endpoints) > 1):
                    is_applicable, applicable_count = True, len(auth_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No multi-role or cookie-backed session flows detected for session puzzling."

            # Input Validation
            elif cid == "WSTG-INPV-01":
                reflected_eps = [e for e in parameterized_endpoints if e in web_endpoints]
                if reflected_eps:
                    is_applicable, applicable_count = True, len(reflected_eps)
                elif parameterized_endpoints and web_endpoints:
                    is_applicable, applicable_count = True, len(parameterized_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No HTML/web endpoints accepting user input parameters found for reflected browser XSS."

            elif cid == "WSTG-INPV-02":
                stored_eps = [
                    e for e in list({x.id: x for x in (form_endpoints + mutation_endpoints)}.values())
                    if e in web_endpoints or e in form_endpoints
                ]
                if stored_eps:
                    is_applicable, applicable_count = True, len(stored_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No HTML state-mutating forms or persistent content submission endpoints identified."

            elif cid in {"WSTG-INPV-04", "WSTG-INPV-05", "WSTG-INPV-11", "WSTG-INPV-12", "WSTG-INPV-17"}:
                if parameterized_endpoints:
                    is_applicable, applicable_count = True, len(parameterized_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No parameterized endpoints (query, form body, JSON, or path variables) discovered."

            elif cid == "WSTG-INPV-06":
                if parameterized_endpoints and auth_endpoints:
                    is_applicable, applicable_count = True, len(auth_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No authentication or directory lookup parameters detected for LDAP injection."

            elif cid == "WSTG-INPV-07":
                if xml_endpoints:
                    is_applicable, applicable_count = True, len(xml_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No XML, SOAP, or SAML input endpoints discovered in attack surface."

            elif cid == "WSTG-INPV-08":
                ssi_eps = [e for e in parameterized_endpoints if e in web_endpoints]
                if ssi_eps:
                    is_applicable, applicable_count = True, len(ssi_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No HTML/server-rendered parameterized web pages discovered for SSI injection."

            elif cid == "WSTG-INPV-09":
                xp = list({e.id: e for e in (xml_endpoints + xpath_param_endpoints)}.values())
                if xp:
                    is_applicable, applicable_count = True, len(xp)
                else:
                    is_explicit_na = True
                    na_reason = "No XML data endpoints or XPath query parameters identified."

            elif cid == "WSTG-INPV-10":
                if mail_contact_endpoints:
                    is_applicable, applicable_count = True, len(mail_contact_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No contact forms, feedback mailers, or email header parameters discovered."

            elif cid == "WSTG-INPV-13":
                if native_c_endpoints and parameterized_endpoints:
                    is_applicable, applicable_count = True, len(native_c_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No native C/C++ CGI binaries or compiled extension handlers detected."

            elif cid == "WSTG-INPV-14":
                if mutation_endpoints:
                    is_applicable, applicable_count = True, len(mutation_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No state-mutating endpoints discovered for second-order/incubated payloads."

            elif cid == "WSTG-INPV-16":
                is_applicable = True
                applicable_count = len(reset_pwd_endpoints) if reset_pwd_endpoints else dom_total

            elif cid == "WSTG-INPV-18":
                if webhook_or_url_endpoints:
                    is_applicable, applicable_count = True, len(webhook_or_url_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No URL-fetching parameters, proxy routes, or webhook callback endpoints identified."

            elif cid == "WSTG-INPV-19":
                if (file_param_or_include_endpoints or has_dynamic_include_runtime) and parameterized_endpoints:
                    is_applicable = True
                    applicable_count = len(file_param_or_include_endpoints) or len(parameterized_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No PHP/dynamic file-include runtime or file/page/include parameters detected."

            # Weak Cryptography
            elif cid == "WSTG-CRYP-02":
                if effective_has_cookies or token_param_endpoints:
                    is_applicable = True
                    applicable_count = len(token_param_endpoints) or cookie_evidence_count
                else:
                    is_explicit_na = True
                    na_reason = "No session cookies or encrypted token parameters detected for padding oracle analysis."

            elif cid == "WSTG-CRYP-04":
                crypto_eps = list({e.id: e for e in (auth_endpoints + token_param_endpoints + api_endpoints)}.values())
                if crypto_eps or effective_has_cookies:
                    is_applicable = True
                    applicable_count = len(crypto_eps) if crypto_eps else cookie_evidence_count
                else:
                    is_explicit_na = True
                    na_reason = "No tokens, authentication hashes, or API cryptographic artifacts observed."

            # Business Logic
            elif cid == "WSTG-BUSL-01":
                busl_eps = list({e.id: e for e in (form_endpoints + mutation_endpoints)}.values())
                if busl_eps:
                    is_applicable, applicable_count = True, len(busl_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No transactional forms or state-changing endpoints discovered."

            elif cid in {"WSTG-BUSL-02", "WSTG-BUSL-06"}:
                if workflow_endpoints:
                    is_applicable, applicable_count = True, len(workflow_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No multi-step transactional, checkout, or approval workflow routes discovered."

            elif cid == "WSTG-BUSL-03":
                if form_endpoints:
                    is_applicable, applicable_count = True, len(form_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No HTML forms or client-submitted form fields discovered."

            elif cid == "WSTG-BUSL-04":
                if mutation_endpoints:
                    is_applicable, applicable_count = True, len(mutation_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No state-mutating (POST/PUT/PATCH/DELETE) endpoints discovered for race-condition testing."

            elif cid == "WSTG-BUSL-05":
                cap_eps = list({e.id: e for e in (mutation_endpoints + api_endpoints)}.values())
                if cap_eps:
                    is_applicable, applicable_count = True, len(cap_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No state-changing or API functional endpoints discovered for velocity-limit checks."

            elif cid in {"WSTG-BUSL-08", "WSTG-BUSL-09"}:
                if upload_endpoints:
                    is_applicable, applicable_count = True, len(upload_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No file upload forms, multipart endpoints, or file parameters identified."

            # Client-Side Testing
            elif cid in {"WSTG-CLNT-01", "WSTG-CLNT-02", "WSTG-CLNT-06", "WSTG-CLNT-11", "WSTG-CLNT-12"}:
                if js_or_web_endpoints:
                    is_applicable, applicable_count = True, len(js_or_web_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No browser HTML pages or client-side JavaScript assets discovered."

            elif cid == "WSTG-CLNT-03":
                html_param_eps = [e for e in parameterized_endpoints if e in web_endpoints]
                if html_param_eps:
                    is_applicable, applicable_count = True, len(html_param_eps)
                else:
                    is_explicit_na = True
                    na_reason = "No parameterized HTML endpoints discovered for HTML injection."

            elif cid == "WSTG-CLNT-04":
                if redirect_param_endpoints:
                    is_applicable, applicable_count = True, len(redirect_param_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No redirect_uri, return_to, next, or URL redirect parameters discovered."

            elif cid == "WSTG-CLNT-05":
                if style_param_endpoints:
                    is_applicable, applicable_count = True, len(style_param_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No customizable CSS, theme, or style parameters discovered."

            elif cid == "WSTG-CLNT-09":
                if web_endpoints:
                    is_applicable, applicable_count = True, len(web_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No interactive HTML pages detected for UI redressing (clickjacking)."

            elif cid == "WSTG-CLNT-10":
                if websocket_endpoints:
                    is_applicable, applicable_count = True, len(websocket_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No WebSocket endpoints (/ws, /socket.io, SignalR) detected in attack surface."

            elif cid == "WSTG-CLNT-13":
                if api_endpoints:
                    is_applicable, applicable_count = True, len(api_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No JSON/API endpoints serving dynamic script-includable payloads discovered."

            # API Testing
            elif cid in {"WSTG-APIT-01", "WSTG-APIT-02", "WSTG-APIT-03", "WSTG-APIT-05", "WSTG-APIT-06"}:
                if api_endpoints:
                    is_applicable, applicable_count = True, len(api_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No REST, GraphQL, or JSON API endpoints discovered in attack surface."

            elif cid == "WSTG-APIT-04":
                if api_id_or_param_endpoints:
                    is_applicable, applicable_count = True, len(api_id_or_param_endpoints)
                elif api_endpoints:
                    is_applicable, applicable_count = True, len(api_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No REST or GraphQL API endpoints discovered for BOLA/BOPLA testing."

            elif cid == "WSTG-APIT-07":
                if not api_endpoints:
                    is_explicit_na = True
                    na_reason = "No REST, GraphQL, or JSON API endpoints discovered in attack surface."
                elif has_https:
                    is_applicable, applicable_count = True, len(api_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "Discovered API runs over plaintext HTTP only; TLS listener required for API cryptography audit."

            elif cid == "WSTG-APIT-08":
                if api_mutation_endpoints:
                    is_applicable, applicable_count = True, len(api_mutation_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No mutating or workflow REST/GraphQL API endpoints discovered."

            elif cid == "WSTG-APIT-09":
                if api_upload_endpoints:
                    is_applicable, applicable_count = True, len(api_upload_endpoints)
                else:
                    is_explicit_na = True
                    na_reason = "No file-upload or multipart API endpoints discovered."

            elif cid == "WSTG-APIT-10":
                if api_endpoints and (cloud_storage_endpoints or webhook_or_url_endpoints):
                    combined_cloud = list({e.id: e for e in (cloud_storage_endpoints + webhook_or_url_endpoints)}.values())
                    is_applicable, applicable_count = True, len(combined_cloud)
                else:
                    is_explicit_na = True
                    na_reason = "No cloud storage integrations or webhook API callbacks detected."

        # Apply state transitions deterministically
        if is_explicit_na:
            if instance.status != "Not Applicable" or not instance.justification:
                instance.status = "Not Applicable"
                instance.justification = na_reason
                instance.applicable_endpoints_count = 0
                instance.updated_at = now
        elif is_applicable and instance.status in {"Not Started", "Not Applicable", "Blocked", "Error"}:
            if instance.status == "Not Applicable":
                instance.justification = None
            instance.status = "Planned"
            instance.applicable_endpoints_count = applicable_count
            instance.updated_at = now
        elif is_applicable and instance.status == "Planned":
            instance.applicable_endpoints_count = applicable_count

    await session.flush()

    planned_total = sum(1 for inst, _ in instances if inst.status == "Planned")
    na_total = sum(1 for inst, _ in instances if inst.status == "Not Applicable")
    failed_total = sum(1 for inst, _ in instances if inst.status == "Failed")

    await session.commit()

    return {
        "project_id": str(project_id),
        "total_instances": len(instances),
        "planned_count": planned_total,
        "not_applicable_count": na_total,
        "failed_count": failed_total,
        "endpoints_analyzed": len(endpoints),
        "summary": (
            f"Recalculated test plan across {len(endpoints)} endpoint(s): "
            f"{planned_total} Planned, {na_total} Not Applicable, {failed_total} Failed."
        ),
    }


class WSTGPlannerService:
    """Service wrapper for WSTG catalog seeding, instance initialization, and plan calculation."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def seed_catalog(self) -> int:
        return await seed_wstg_catalog(self.session)

    async def initialize_project_instances(self, project_id: uuid.UUID) -> List[WSTGTestInstance]:
        await initialize_project_wstg_instances(self.session, project_id)
        stmt = select(WSTGTestInstance).where(WSTGTestInstance.project_id == project_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def recalculate_test_plan(self, project_id: uuid.UUID) -> Dict[str, Any]:
        return await recalculate_project_test_plan(self.session, project_id)


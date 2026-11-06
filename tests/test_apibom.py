"""Tests for API-BOM module."""

from __future__ import annotations

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Layer 1: Framework extractors
# ---------------------------------------------------------------------------


class TestFastAPIExtractor:
    """Test FastAPI route extraction."""

    def test_detect_fastapi(self):
        from xbom.modules.apibom.extractors.python import FastAPIExtractor

        ext = FastAPIExtractor()
        assert ext.detect("from fastapi import FastAPI")
        assert ext.detect("import fastapi")
        assert not ext.detect("import flask")

    def test_extract_routes(self):
        from xbom.modules.apibom.extractors.python import FastAPIExtractor

        fixture = FIXTURES / "python_fastapi" / "main.py"
        content = fixture.read_text()
        ext = FastAPIExtractor()

        endpoints = ext.extract(fixture, content, "main.py")

        assert len(endpoints) >= 3
        paths = {ep.path for ep in endpoints}
        assert "/api/health" in paths
        assert "/api/chat" in paths
        assert "/api/users/{user_id}" in paths

        methods = {ep.method for ep in endpoints}
        assert "GET" in methods
        assert "POST" in methods

        for ep in endpoints:
            assert ep.framework == "fastapi"
            assert ep.category == "internal-endpoint"
            assert ep.source_file == "main.py"
            assert ep.source_line > 0

    def test_auth_is_per_route(self):
        from xbom.modules.apibom.extractors.python import FastAPIExtractor

        # One authenticated route must not mark its unauthenticated neighbours as authenticated
        content = "\n".join([
            "from fastapi import APIRouter, Depends",
            "router = APIRouter(tags=['admin'])",
            "",
            "@router.get('/dashboard')",
            "def dashboard(user=Depends(get_current_user)):",
            "    return {}",
            "",
            "@router.get('/debug/config')",
            "def debug_config():",
            "    return {}",
            "",
            "@router.delete('/users/{user_id}')",
            "async def delete_user(",
            "    user_id: str,",
            "    user=Depends(get_current_user),",
            ") -> dict:",
            "    return {}",
        ])
        endpoints = FastAPIExtractor().extract(Path("admin.py"), content, "admin.py")
        auth_by_path = {ep.path: ep.auth_detected for ep in endpoints}
        assert auth_by_path == {"/dashboard": True, "/debug/config": False, "/users/{user_id}": True}

    def test_router_dependencies_cover_all_routes(self):
        from xbom.modules.apibom.extractors.python import FastAPIExtractor

        content = "\n".join([
            "from fastapi import APIRouter, Depends",
            "router = APIRouter(prefix='/admin', dependencies=[Depends(get_current_user)])",
            "",
            "@router.get('/stats')",
            "def stats():",
            "    return {}",
        ])
        endpoints = FastAPIExtractor().extract(Path("admin.py"), content, "admin.py")
        assert [(ep.path, ep.auth_detected) for ep in endpoints] == [("/admin/stats", True)]

    def test_sample_admin_debug_route_unauthenticated(self):
        from xbom.modules.apibom.extractors.python import FastAPIExtractor

        fixture = Path(__file__).parent.parent / "sample" / "app" / "admin.py"
        endpoints = FastAPIExtractor().extract(fixture, fixture.read_text(), "app/admin.py")
        unauthenticated = [ep.path for ep in endpoints if not ep.auth_detected]
        assert unauthenticated == ["/debug/config"]


class TestDjangoExtractor:
    """Test Django route extraction."""

    def test_auth_is_per_route(self):
        from xbom.modules.apibom.extractors.python import DjangoExtractor

        content = "\n".join([
            "from django.urls import path",
            "from django.contrib.auth.decorators import login_required",
            "urlpatterns = [",
            "    path('account/', login_required(views.account)),",
            "    path('about/', views.about),",
            "]",
        ])
        endpoints = DjangoExtractor().extract(Path("urls.py"), content, "urls.py")
        auth_by_path = {ep.path: ep.auth_detected for ep in endpoints}
        assert auth_by_path["/account/"] is True
        assert auth_by_path["/about/"] is False


class TestFlaskExtractor:
    """Test Flask route extraction."""

    def test_detect_flask(self):
        from xbom.modules.apibom.extractors.python import FlaskExtractor

        ext = FlaskExtractor()
        assert ext.detect("from flask import Flask")
        assert not ext.detect("from fastapi import FastAPI")

    def test_extract_routes(self):
        from xbom.modules.apibom.extractors.python import FlaskExtractor

        fixture = FIXTURES / "python_flask" / "app.py"
        content = fixture.read_text()
        ext = FlaskExtractor()

        endpoints = ext.extract(fixture, content, "app.py")

        assert len(endpoints) >= 3
        paths = {ep.path for ep in endpoints}
        # Blueprint with url_prefix="/api/v1"
        assert any("/health" in p for p in paths)
        assert any("/users" in p for p in paths)

        for ep in endpoints:
            assert ep.framework == "flask"
            assert ep.category == "internal-endpoint"

    def test_auth_detection(self):
        from xbom.modules.apibom.extractors.python import FlaskExtractor

        fixture = FIXTURES / "python_flask" / "app.py"
        content = fixture.read_text()
        ext = FlaskExtractor()

        endpoints = ext.extract(fixture, content, "app.py")
        # Only the routes decorated with @login_required are authenticated
        auth_by_path = {ep.path: ep.auth_detected for ep in endpoints}
        assert auth_by_path["/api/v1/users"] is True
        assert auth_by_path["/api/v1/users/<int:user_id>"] is True
        assert auth_by_path["/api/v1/health"] is False
        assert auth_by_path["/api/v1/admin/dashboard"] is False


class TestExpressExtractor:
    """Test Express.js route extraction."""

    def test_detect_express(self):
        from xbom.modules.apibom.extractors.javascript import ExpressExtractor

        ext = ExpressExtractor()
        assert ext.detect("const express = require('express');")
        assert ext.detect("import express from 'express'")
        assert not ext.detect("const http = require('http');")

    def test_extract_routes(self):
        from xbom.modules.apibom.extractors.javascript import ExpressExtractor

        fixture = FIXTURES / "js_express" / "app.js"
        content = fixture.read_text()
        ext = ExpressExtractor()

        endpoints = ext.extract(fixture, content, "app.js")

        assert len(endpoints) >= 4
        paths = {ep.path for ep in endpoints}
        assert "/api/health" in paths
        assert "/api/users" in paths
        assert "/api/users/:id" in paths

        methods = {ep.method for ep in endpoints}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

        for ep in endpoints:
            assert ep.framework == "express"
            assert ep.source_file == "app.js"

    def test_auth_detection(self):
        from xbom.modules.apibom.extractors.javascript import ExpressExtractor

        fixture = FIXTURES / "js_express" / "app.js"
        content = fixture.read_text()
        ext = ExpressExtractor()

        endpoints = ext.extract(fixture, content, "app.js")
        # Only routes that pass authMiddleware are authenticated
        auth_by_route = {(ep.method, ep.path): ep.auth_detected for ep in endpoints}
        assert auth_by_route[("GET", "/api/health")] is False
        assert auth_by_route[("GET", "/api/users")] is True
        assert auth_by_route[("DELETE", "/api/users/:id")] is True

    def test_app_use_auth_applies_to_later_routes(self):
        from xbom.modules.apibom.extractors.javascript import ExpressExtractor

        content = "\n".join([
            "const express = require('express');",
            "const router = express.Router();",
            "router.get('/health', (req, res) => res.send('ok'));",
            "router.use('/admin', requireAuth);",
            "router.get('/public', (req, res) => res.send('hi'));",
            "router.get('/admin/stats', (req, res) => res.json({}));",
            "router.use(requireAuth);",
            "router.get('/me', (req, res) => res.json({}));",
        ])
        endpoints = ExpressExtractor().extract(Path("app.js"), content, "app.js")
        auth_by_path = {ep.path: ep.auth_detected for ep in endpoints}
        assert auth_by_path == {"/health": False, "/public": False, "/admin/stats": True, "/me": True}


# ---------------------------------------------------------------------------
# Layer 2: OpenAPI spec parser
# ---------------------------------------------------------------------------


class TestSpecParser:
    """Test OpenAPI spec file parsing."""

    def test_parse_openapi_spec(self):
        from xbom.modules.apibom.spec_parser import parse_api_specs

        fixture = FIXTURES / "openapi_spec"
        endpoints, spec_components = parse_api_specs(fixture)

        # 5 operations: GET /health, GET /users, POST /users, GET /users/{id}, DELETE /users/{id}
        assert len(endpoints) == 5

        paths = {ep.path for ep in endpoints}
        assert "/health" in paths
        assert "/users" in paths
        assert "/users/{id}" in paths

        methods = {ep.method for ep in endpoints}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

        for ep in endpoints:
            assert ep.framework == "openapi-spec"
            assert ep.category == "api-spec"

    def test_spec_component_created(self):
        from xbom.modules.apibom.spec_parser import parse_api_specs

        fixture = FIXTURES / "openapi_spec"
        _, spec_components = parse_api_specs(fixture)

        assert len(spec_components) == 1
        comp = spec_components[0]
        assert comp["type"] == "data"
        assert "openapi.yaml" in comp["name"]

        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["xbom:api:category"] == "api-spec"
        assert props["xbom:api:spec_version"] == "3.0.3"
        assert props["xbom:api:spec_title"] == "Test API"
        assert props["xbom:api:spec_api_version"] == "2.0"
        assert props["xbom:api:spec_endpoint_count"] == "5"
        assert props["xbom:api:spec_has_security"] == "true"

    def test_auth_detection_in_spec(self):
        from xbom.modules.apibom.spec_parser import parse_api_specs

        fixture = FIXTURES / "openapi_spec"
        endpoints, _ = parse_api_specs(fixture)

        # /health has no security, others do
        health = [ep for ep in endpoints if ep.path == "/health"]
        assert len(health) == 1
        # Health should still detect auth (global securitySchemes defined)
        # but the operation itself has no security block, so auth_detected depends on global

        secured = [ep for ep in endpoints if ep.path == "/users" and ep.method == "GET"]
        assert len(secured) == 1
        assert secured[0].auth_detected is True


# ---------------------------------------------------------------------------
# Layer 3: Client detector
# ---------------------------------------------------------------------------


class TestClientDetector:
    """Test outbound HTTP client call detection."""

    def test_detect_requests_calls(self):
        from xbom.modules.apibom.client_detector import detect_client_calls

        fixture = FIXTURES / "external_calls"
        endpoints = detect_client_calls(fixture)

        assert len(endpoints) >= 3  # at least 3 unique hosts
        hosts = {ep.host for ep in endpoints}
        assert "api.example.com" in hosts
        assert "api.openai.com" in hosts

        for ep in endpoints:
            assert ep.category == "external-dependency"
            assert ep.host

    def test_no_tls_detection(self):
        from xbom.modules.apibom.client_detector import detect_client_calls

        fixture = FIXTURES / "external_calls"
        endpoints = detect_client_calls(fixture)

        insecure = [ep for ep in endpoints if ep.path.startswith("http://")]
        assert len(insecure) >= 1


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


class TestApibomRisk:
    """Test API-BOM risk scoring."""

    def test_score_no_auth(self):
        from xbom.modules.apibom.risk import score_risk

        assessment = score_risk(["no_authentication"])
        assert assessment.score == 30
        assert assessment.severity.value == "medium"
        assert len(assessment.factors) == 1

    def test_score_multiple_flags(self):
        from xbom.modules.apibom.risk import score_risk

        assessment = score_risk(["no_authentication", "admin_endpoint_exposed", "sensitive_data_exposure"])
        assert assessment.score == 75
        assert assessment.severity.value == "high"

    def test_score_critical(self):
        from xbom.modules.apibom.risk import score_risk

        assessment = score_risk(
            [
                "no_authentication",
                "sensitive_data_exposure",
                "external_api_no_tls",
                "admin_endpoint_exposed",
            ]
        )
        assert assessment.score >= 76
        assert assessment.severity.value == "critical"

    def test_score_empty(self):
        from xbom.modules.apibom.risk import score_risk

        assessment = score_risk([])
        assert assessment.score == 0
        assert assessment.severity.value == "info"

    def test_to_properties(self):
        from xbom.modules.apibom.risk import score_risk

        assessment = score_risk(["no_authentication"])
        props = assessment.to_properties()
        names = {p["name"] for p in props}
        assert "xbom:api:risk_score" in names
        assert "xbom:api:risk_severity" in names
        assert "xbom:api:risk_factors" in names


# ---------------------------------------------------------------------------
# Integration: full scanner
# ---------------------------------------------------------------------------


class TestApibomScanner:
    """Integration test: run ApibomModule on fixtures."""

    def test_scan_fastapi_project(self):
        from xbom.models import ScanConfig
        from xbom.modules.apibom.scanner import ApibomModule

        module = ApibomModule()
        assert module.bom_type.value == "apibom"
        assert module.name == "API-BOM"
        assert module.required_tools() == []

        config = ScanConfig(
            target=str(FIXTURES / "python_fastapi"),
            bom_types=[],
        )

        bom = module.scan(FIXTURES / "python_fastapi", config)

        # Check BOM structure
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"

        # Should have services (internal endpoints)
        services = bom.get("services", [])
        assert len(services) >= 1

        svc = services[0]
        assert "endpoints" in svc
        assert len(svc["endpoints"]) >= 3

        props = {p["name"]: p["value"] for p in svc.get("properties", [])}
        assert props["xbom:api:framework"] == "fastapi"

        # BOM-level properties
        bom_props = {p["name"]: p["value"] for p in bom.get("properties", [])}
        assert "xbom:api:total_endpoints" in bom_props
        assert int(bom_props["xbom:api:total_endpoints"]) >= 3

    def test_scan_flask_project(self):
        from xbom.models import ScanConfig
        from xbom.modules.apibom.scanner import ApibomModule

        module = ApibomModule()
        config = ScanConfig(target=str(FIXTURES / "python_flask"), bom_types=[])

        bom = module.scan(FIXTURES / "python_flask", config)

        services = bom.get("services", [])
        assert len(services) >= 1

        # Should detect flask framework
        all_props = {}
        for svc in services:
            for p in svc.get("properties", []):
                all_props[p["name"]] = p["value"]
        assert all_props.get("xbom:api:framework") == "flask"

    def test_scan_express_project(self):
        from xbom.models import ScanConfig
        from xbom.modules.apibom.scanner import ApibomModule

        module = ApibomModule()
        config = ScanConfig(target=str(FIXTURES / "js_express"), bom_types=[])

        bom = module.scan(FIXTURES / "js_express", config)

        services = bom.get("services", [])
        assert len(services) >= 1

    def test_scan_openapi_spec(self):
        from xbom.models import ScanConfig
        from xbom.modules.apibom.scanner import ApibomModule

        module = ApibomModule()
        config = ScanConfig(target=str(FIXTURES / "openapi_spec"), bom_types=[])

        bom = module.scan(FIXTURES / "openapi_spec", config)

        # Should have spec components
        components = bom.get("components", [])
        spec_comps = [c for c in components if c.get("type") == "data"]
        assert len(spec_comps) >= 1

    def test_scan_external_calls(self):
        from xbom.models import ScanConfig
        from xbom.modules.apibom.scanner import ApibomModule

        module = ApibomModule()
        config = ScanConfig(target=str(FIXTURES / "external_calls"), bom_types=[])

        bom = module.scan(FIXTURES / "external_calls", config)

        # Should have external dependency components
        components = bom.get("components", [])
        ext_comps = [c for c in components if c.get("type") == "service"]
        assert len(ext_comps) >= 1

        # Check external references
        for comp in ext_comps:
            assert "externalReferences" in comp
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            assert props["xbom:api:category"] == "external-dependency"

"""
Aegis PQC — demonstration application manifests.

Extends the demo estate with realistic dependency manifests so the dependency
adapter has genuine material to parse.

DESIGN INTENT
-------------
Four applications, chosen so the scan shows *differentiation* rather than a
uniform wall of findings. If every application looked the same, the
demonstration would prove the scanner runs but not that it discriminates.

    payments-api    Classical asymmetric cryptography, long-lived financial
                    data. The headline critical case.
    legacy-auth     A genuinely unmaintained package plus libraries providing
                    MD5 and DES. Shows deprecated-dependency detection.
    pqc-pilot       Post-quantum capable dependencies. Proves the scanner
                    recognises the good case, not only failures.
    content-portal  No cryptographic dependencies at all. Proves unknown
                    packages produce no finding rather than a guess.

Every manifest is synthetic. They contain no credentials, tokens, private keys,
or real internal package names. Versions are chosen to exercise specific paths —
pinned, ranged, unpinned, and property-referenced — not to imply any real
deployment.

The manifests are written as literal text rather than generated, because the
scanner's job is to parse what a developer actually writes: inline comments,
extras, environment markers, and inconsistent pinning.
"""

from __future__ import annotations

from pathlib import Path

# ==========================================================================
# payments-api — classical asymmetric, long-lived data
# ==========================================================================

PAYMENTS_REQUIREMENTS = """\
# payments-api — settlement and card processing
# Data retention: 25 years (regulatory)

cryptography==42.0.5
pyOpenSSL==24.0.0
PyJWT==1.7.1
requests==2.31.0
fastapi==0.110.0
pydantic>=2.6,<3.0
sqlalchemy==2.0.29
"""

PAYMENTS_POLICY_NOTE = """\
payments-api declares pinned versions throughout. PyJWT 1.7.1 predates the
2.0.0 recommendation, which the scanner reports against the knowledge base.
"""


# ==========================================================================
# legacy-auth — deprecated dependencies
# ==========================================================================

LEGACY_AUTH_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.northwind</groupId>
  <artifactId>legacy-auth</artifactId>
  <version>3.4.2</version>

  <properties>
    <bouncycastle.version>1.68</bouncycastle.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk15on</artifactId>
      <version>${bouncycastle.version}</version>
    </dependency>
    <dependency>
      <groupId>commons-codec</groupId>
      <artifactId>commons-codec</artifactId>
      <version>1.11</version>
    </dependency>
    <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt</artifactId>
      <version>0.9.1</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.31</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""

LEGACY_AUTH_REQUIREMENTS = """\
# legacy-auth — internal staff token service
# Scheduled for decommission; still in production

pycrypto==2.6.1
M2Crypto==0.38.0
paramiko==3.4.0
flask==3.0.2
"""


# ==========================================================================
# pqc-pilot — post-quantum capable
# ==========================================================================

PQC_PILOT_GO_MOD = """\
module github.com/northwind/pqc-pilot

go 1.22

require (
\tgithub.com/cloudflare/circl v1.3.7
\tgolang.org/x/crypto v0.21.0
\tgithub.com/golang-jwt/jwt/v5 v5.2.1
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/stretchr/testify v1.9.0 // indirect
)
"""

PQC_PILOT_REQUIREMENTS = """\
# pqc-pilot — post-quantum migration pilot service
# Uses cryptography>=49 for ML-KEM support

cryptography>=49.0.0
pynacl==1.5.0
uvicorn==0.29.0
"""


# ==========================================================================
# content-portal — no cryptographic dependencies
# ==========================================================================

CONTENT_PORTAL_PACKAGE_JSON = """\
{
  "name": "content-portal",
  "version": "2.1.0",
  "description": "Public marketing and documentation site",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "next": "14.1.4",
    "tailwindcss": "^3.4.1",
    "date-fns": "^3.6.0"
  },
  "devDependencies": {
    "typescript": "^5.4.3",
    "eslint": "^8.57.0"
  }
}
"""


# ==========================================================================
# mobile-gateway — mixed npm cryptographic dependencies
# ==========================================================================

MOBILE_GATEWAY_PACKAGE_JSON = """\
{
  "name": "mobile-gateway",
  "version": "5.2.1",
  "description": "Mobile client API gateway",
  "dependencies": {
    "express": "^4.19.2",
    "jsonwebtoken": "^8.5.1",
    "node-forge": "0.10.0",
    "elliptic": "^6.5.4",
    "axios": "^1.6.8"
  },
  "devDependencies": {
    "crypto-js": "^3.3.0",
    "jest": "^29.7.0"
  }
}
"""


# ==========================================================================
# Policy file — business context and component path mapping
# ==========================================================================
# Declares which directory each application owns, so attribution does not
# depend on the directory-name heuristic, and supplies the business context the
# risk engine will need in Phase 7.
#
# Deliberately partial: content-portal declares nothing, so the scan
# demonstrates the documented-default path with provenance marked accordingly.

DEMO_POLICY = """\
# Aegis PQC — declared application context
#
# path:                 directory this component owns, relative to scan root
# data_lifetime_years:  how long the data must stay confidential
# data_sensitivity:     critical | high | medium | low
# business_criticality: operational importance, separate from sensitivity

payments-api:
  path: payments-api
  data_lifetime_years: 25
  data_sensitivity: critical
  business_criticality: critical
  notes: Card settlement records under regulatory retention

legacy-auth:
  path: legacy-auth
  data_lifetime_years: 30
  data_sensitivity: critical
  business_criticality: high
  notes: Staff authentication tokens, decommission pending

pqc-pilot:
  path: pqc-pilot
  data_lifetime_years: 30
  data_sensitivity: high
  business_criticality: medium
  notes: Post-quantum migration pilot

mobile-gateway:
  path: mobile-gateway
  data_lifetime_years: 8
  data_sensitivity: high
  business_criticality: high
  notes: Mobile client traffic termination
"""


#: Manifest files written into the estate: relative path to contents.
APPLICATION_MANIFESTS: dict[str, str] = {
    "payments-api/requirements.txt": PAYMENTS_REQUIREMENTS,
    "legacy-auth/pom.xml": LEGACY_AUTH_POM,
    "legacy-auth/requirements.txt": LEGACY_AUTH_REQUIREMENTS,
    "pqc-pilot/go.mod": PQC_PILOT_GO_MOD,
    "pqc-pilot/requirements.txt": PQC_PILOT_REQUIREMENTS,
    "content-portal/package.json": CONTENT_PORTAL_PACKAGE_JSON,
    "mobile-gateway/package.json": MOBILE_GATEWAY_PACKAGE_JSON,
}

#: Applications expected to yield at least one cryptographic finding.
CRYPTO_APPLICATIONS: frozenset[str] = frozenset(
    {"payments-api", "legacy-auth", "pqc-pilot", "mobile-gateway"}
)

#: Applications that declare dependencies but none cryptographic. Their presence
#: is what proves unknown packages produce no finding.
NON_CRYPTO_APPLICATIONS: frozenset[str] = frozenset({"content-portal"})


def write_application_manifests(root: Path) -> list[Path]:
    """Write the demonstration manifests and policy file into ``root``.

    Args:
        root: Estate root directory.

    Returns:
        Paths written, sorted.
    """
    written: list[Path] = []

    for relative, contents in APPLICATION_MANIFESTS.items():
        path = root / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        written.append(path)

    policy = root / "aegis_policy.yaml"
    policy.write_text(DEMO_POLICY, encoding="utf-8")
    written.append(policy)

    return sorted(written)

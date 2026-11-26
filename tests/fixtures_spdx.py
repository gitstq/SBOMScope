"""测试用 SPDX / CycloneDX 样本数据。"""

SPDX_CLEAN = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "clean-app",
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: SBOMScope-Test"],
    "packages": [
        {
            "name": "requests",
            "SPDXID": "SPDXRef-Package-requests",
            "versionInfo": "2.31.0",
            "downloadLocation": "NOASSERTION",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "Copyright 2019 Kenneth Reitz",
            "supplier": "Organization: Python Software Foundation",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": "a" * 64}
            ],
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "PURL",
                    "referenceLocator": "pkg:pypi/requests@2.31.0",
                }
            ],
        }
    ],
}

SPDX_DIRTY = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "dirty-app",
    "packages": [
        {
            "name": "foo",
            "SPDXID": "SPDXRef-Package-foo",
            "licenseDeclared": "NOASSERTION",
            "checksums": [{"algorithm": "MD5", "checksumValue": "xyz"}],
            "externalRefs": [
                {"referenceType": "PURL", "referenceLocator": "NOT-A-PURL"}
            ],
        },
        {
            "name": "bar",
            "SPDXID": "SPDXRef-Package-bar",
            "versionInfo": "1.0.0",
            "licenseDeclared": "GPL-3.0",
            "externalRefs": [
                {"referenceType": "PURL", "referenceLocator": "pkg:pypi/bar@1.0.0"}
            ],
        },
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-Package-foo",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-missing",
        }
    ],
}

CDX_CLEAN = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "metadata": {
        "timestamp": "2026-01-01T00:00:00Z",
        "component": {"name": "demo", "version": "1.0.0", "type": "application"},
        "tools": [{"name": "SBOMScope-Test"}],
    },
    "components": [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "bom-ref": "pkg:npm/lodash@4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": [{"license": {"id": "MIT"}}],
            "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
            "supplier": {"name": "lodash contributors"},
        }
    ],
    "dependencies": [{"ref": "pkg:npm/lodash@4.17.21", "dependsOn": []}],
}

CDX_DIRTY = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "evil",
            "version": "0.1",
            "purl": "pkg:npm/evil@0.1",
            "licenses": [{"license": {"name": "SomeWeirdLicense"}}],
            "hashes": [{"alg": "SHA1", "content": "c" * 40}],
        },
        {
            "type": "library",
            "name": "evil",
            "version": "0.1",
            "purl": "pkg:npm/evil@0.1",
        },
    ],
}

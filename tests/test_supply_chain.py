"""Real bounded inventory normalization and complete dependency comparisons."""
import copy
import json
import unittest
from unittest.mock import patch

from cyber_platform import supply_chain as supply
from cyber_platform.store import encode


class SupplyChainTests(unittest.TestCase):
    def raw(self, value):
        return encode(value).encode()

    def analyze(self, value):
        return supply.analyze(self.raw(value))

    def spdx(self):
        return {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "Synthetic SBOM",
                "packages": [{"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1.0",
                              "licenseDeclared": "MIT", "licenseConcluded": "NOASSERTION",
                              "checksums": [{"algorithm": "SHA256", "checksumValue": "A" * 64}],
                              "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:generic/app@1.0"}]},
                             {"SPDXID": "SPDXRef-lib", "name": "lib", "versionInfo": "2.0", "licenseDeclared": "Apache-2.0"}],
                "relationships": [{"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-lib"}]}

    def test_cyclonedx_sample_normalizes_real_dependencies_and_hashes(self):
        result = self.analyze(supply.sample())
        self.assertEqual(result["schema"], "was.supply-chain/1")
        self.assertEqual(result["format"], "CycloneDX-1.6")
        self.assertEqual(result["component_count"], 2)
        self.assertEqual(result["dependencies"], [{"source": "app", "target": "library"}])
        self.assertEqual(result["summary"]["missing_hashes"], 0)
        self.assertEqual(result["issues"], [])
        self.assertFalse(result["network"])
        self.assertEqual(result["vulnerability_assessment"], "source_claims_only_not_live_audit")

    def test_spdx_packages_license_checksum_and_both_dependency_directions(self):
        value = self.spdx()
        first = self.analyze(value)
        self.assertEqual(first["components"][0]["hashes"], {"SHA-256": "a" * 64})
        self.assertEqual(first["components"][0]["licenses"], ["MIT"])
        self.assertEqual(first["components"][0]["purl"], "pkg:generic/app@1.0")
        value["relationships"] = [{"spdxElementId": "SPDXRef-lib", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-app"}]
        self.assertEqual(self.analyze(value)["dependencies"], first["dependencies"])

    def test_nested_and_metadata_components_are_part_of_the_inventory(self):
        value = supply.sample()
        root = value["components"].pop(0)
        root["components"] = value["components"]
        value["components"] = []
        value["metadata"] = {"component": root}
        result = self.analyze(value)
        self.assertEqual(result["component_count"], 2)
        self.assertEqual(result["graph"]["nodes"], ["app", "library"])

    def test_supported_cyclonedx_versions_and_spdx_relationship_omissions(self):
        value = supply.sample()
        value["specVersion"] = "1.5"
        self.assertEqual(self.analyze(value)["format"], "CycloneDX-1.5")
        value = self.spdx()
        value["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-app"})
        self.assertEqual(self.analyze(value)["summary"]["ignored_relationships"], 1)

    def test_missing_metadata_is_reported_without_safety_or_license_claim(self):
        value = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"bom-ref": "empty", "name": "example"}]}
        result = self.analyze(value)
        self.assertEqual({i["code"] for i in result["issues"]}, {"missing_version", "missing_license", "missing_hash"})
        self.assertEqual(result["summary"]["declared_vulnerabilities"], 0)
        self.assertNotIn("safe", result)
        self.assertNotIn("vulnerability_free", result)

    def test_duplicate_identifiers_and_ambiguous_json_are_rejected(self):
        value = supply.sample()
        value["components"].append(copy.deepcopy(value["components"][0]))
        with self.assertRaises(ValueError):
            self.analyze(value)
        for raw in [b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6"}',
                    b'{"bomFormat":"CycloneDX","specVersion":"1.6","unknown":NaN}',
                    b'{"bomFormat":"CycloneDX","specVersion":"1.6","unknown":1e999}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                supply.analyze(raw)

    def test_unsupported_or_mixed_formats_and_versions_are_explicit_errors(self):
        for value in [[], {}, {"bomFormat": "CycloneDX", "specVersion": "1.4"}, {"spdxVersion": "SPDX-3.0"},
                      {"bomFormat": "CycloneDX", "specVersion": "1.6", "spdxVersion": "SPDX-2.3"}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.analyze(value)

    def test_unknown_external_and_self_dependency_references_are_rejected(self):
        for target in ["missing", "app", "DocumentRef-external:SPDXRef-package"]:
            value = supply.sample()
            value["dependencies"][0]["dependsOn"] = [target]
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.analyze(value)
        value = supply.sample()
        value["dependencies"] = [{"ref": "unknown", "dependsOn": []}]
        with self.assertRaises(ValueError):
            self.analyze(value)

    def test_cycles_identify_only_actual_cycle_members_not_downstream_nodes(self):
        value = supply.sample()
        value["components"].append({"bom-ref": "sink", "name": "sink"})
        value["dependencies"] = [{"ref": "app", "dependsOn": ["library"]}, {"ref": "library", "dependsOn": ["app", "sink"]}]
        result = self.analyze(value)
        self.assertEqual(result["graph"]["cycles"], ["app", "library"])
        self.assertEqual([i["component_id"] for i in result["issues"] if i["code"] == "dependency_cycle"], ["app", "library"])

    def test_thousand_component_chain_does_not_use_recursive_graph_traversal(self):
        value = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                 "components": [{"bom-ref": str(i), "name": "item-" + str(i)} for i in range(1000)],
                 "dependencies": [{"ref": str(i), "dependsOn": [str(i + 1)]} for i in range(999)]}
        result = self.analyze(value)
        self.assertEqual(result["summary"]["dependencies"], 999)
        self.assertEqual(result["graph"]["cycles"], [])

    def test_hashes_require_supported_algorithm_exact_length_and_no_duplicate(self):
        for hashes in [[{"alg": "SHA-256", "content": "bad"}], [{"alg": "unknown", "content": "a" * 64}],
                       [{"alg": "SHA-256", "content": "a" * 64}] * 2]:
            value = supply.sample()
            value["components"][0]["hashes"] = hashes
            with self.subTest(hashes=hashes), self.assertRaises(ValueError):
                self.analyze(value)

    def test_same_package_and_version_with_conflicting_hashes_is_visible(self):
        value = supply.sample()
        duplicate = copy.deepcopy(value["components"][0])
        duplicate["bom-ref"] = "second-copy"
        duplicate["hashes"][0]["content"] = "c" * 64
        value["components"].append(duplicate)
        result = self.analyze(value)
        self.assertEqual([i["component_id"] for i in result["issues"] if i["code"] == "conflicting_hash"], ["app", "second-copy"])

    def test_cyclonedx_license_choices_and_spdx_noassertion_are_distinguished(self):
        value = supply.sample()
        value["components"][0]["licenses"] = [{"expression": "MIT OR Apache-2.0"}, {"license": {"name": "Private owner declaration"}}]
        self.assertEqual(self.analyze(value)["components"][0]["licenses"], ["MIT OR Apache-2.0", "Private owner declaration"])
        value["components"][0]["licenses"] = [{"expression": "MIT", "license": {"id": "MIT"}}]
        with self.assertRaises(ValueError):
            self.analyze(value)
        value = self.spdx()
        value["packages"][0]["licenseDeclared"] = "NOASSERTION"
        self.assertEqual(self.analyze(value)["components"][0]["licenses"], [])

    def test_vulnerability_declarations_keep_scores_and_are_never_verified(self):
        value = supply.sample()
        value["vulnerabilities"] = [{"id": "CVE-2099-0001", "affects": [{"ref": "library"}], "ratings": [{"severity": "high", "score": 8.5, "method": "CVSSv3"}]}]
        result = self.analyze(value)
        self.assertEqual(result["summary"]["declared_vulnerabilities"], 1)
        self.assertEqual(result["vulnerabilities"][0]["declared_ratings"], [{"severity": "high", "score": 8.5, "method": "CVSSv3"}])
        self.assertEqual(result["vulnerabilities"][0]["verification"], "source_claim_only")

    def test_vulnerability_bad_references_scores_and_duplicate_ids_fail(self):
        for patch_value in [{"affects": [{"ref": "missing"}]}, {"ratings": [{"score": True}]}, {"ratings": [{"score": 11}]}, {"ratings": [{"score": -1}]}]:
            value = supply.sample()
            value["vulnerabilities"] = [{"id": "CVE-2099-0001", **patch_value}]
            with self.subTest(patch_value=patch_value), self.assertRaises(ValueError):
                self.analyze(value)
        value["vulnerabilities"] = [{"id": "same"}, {"id": "same"}]
        with self.assertRaises(ValueError):
            self.analyze(value)

    def test_malformed_component_types_purls_and_identifiers_fail(self):
        for field, bad in [("name", []), ("version", True), ("purl", "https://example.test"), ("purl", "pkg:invalid"), ("bom-ref", "bad\nref")]:
            value = supply.sample()
            value["components"][0][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                self.analyze(value)
        value = self.spdx()
        value["packages"][0]["SPDXID"] = "arbitrary"
        with self.assertRaises(ValueError):
            self.analyze(value)
        value = self.spdx()
        del value["packages"][0]["externalRefs"][0]["referenceLocator"]
        with self.assertRaises(ValueError):
            self.analyze(value)

    def test_component_dependency_input_and_json_depth_limits_fail_whole_analysis(self):
        with patch.dict(supply.LIMITS, components=1), self.assertRaises(ValueError):
            self.analyze(supply.sample())
        value = supply.sample()
        value["dependencies"][0]["dependsOn"] = ["library", "library"]
        with patch.dict(supply.LIMITS, dependencies=1), self.assertRaises(ValueError):
            self.analyze(value)
        with patch.dict(supply.LIMITS, input_bytes=10), self.assertRaises(ValueError):
            self.analyze(supply.sample())
        value = supply.sample()
        nested = value
        for _ in range(40):
            nested["unknown_metadata"] = {}
            nested = nested["unknown_metadata"]
        with self.assertRaises(ValueError):
            self.analyze(value)

    def test_spdx_unknown_dependency_is_not_silently_ignored_as_external(self):
        value = self.spdx()
        value["relationships"][0]["relatedSpdxElement"] = "DocumentRef-other:SPDXRef-lib"
        with self.assertRaises(ValueError):
            self.analyze(value)

    def test_dependency_duplicates_normalize_once_and_output_is_deterministic(self):
        value = supply.sample()
        value["dependencies"][0]["dependsOn"] = ["library", "library"]
        first = self.analyze(value)
        self.assertEqual(len(first["dependencies"]), 1)
        value["components"].reverse()
        second = self.analyze(value)
        self.assertEqual(first["components"], second["components"])
        self.assertEqual(first["dependencies"], second["dependencies"])

    def test_diff_reports_component_fields_and_edge_changes_completely(self):
        before = supply.sample()
        after = copy.deepcopy(before)
        after["components"][1]["version"] = "2.1.0"
        after["dependencies"] = []
        result = supply.diff(self.raw(before), self.raw(after))
        self.assertTrue(result["complete"])
        self.assertFalse(result["normalized_inventory_equal"])
        self.assertEqual(result["changed_components"], [{"id": "library", "fields": ["version"]}])
        self.assertEqual(result["removed_dependencies"], [{"source": "app", "target": "library"}])

    def test_diff_distinguishes_component_addition_and_removal(self):
        before = supply.sample()
        after = copy.deepcopy(before)
        after["components"][1]["bom-ref"] = "replacement"
        after["dependencies"][0]["dependsOn"] = ["replacement"]
        result = supply.diff(self.raw(before), self.raw(after))
        self.assertEqual(result["added_components"], ["replacement"])
        self.assertEqual(result["removed_components"], ["library"])
        self.assertEqual(result["added_dependencies"], [{"source": "app", "target": "replacement"}])

    def test_diff_inventory_equality_is_not_raw_document_equality(self):
        value = supply.sample()
        reversed_value = copy.deepcopy(value)
        reversed_value["components"].reverse()
        result = supply.diff(self.raw(value), self.raw(reversed_value))
        self.assertTrue(result["normalized_inventory_equal"])
        self.assertNotEqual(result["left_sha256"], result["right_sha256"])
        self.assertNotIn("equal", result)

    def test_diff_vulnerability_rating_change_is_not_equal(self):
        before = supply.sample()
        before["vulnerabilities"] = [{"id": "CVE-2099-0001", "ratings": [{"score": 5}]}]
        after = copy.deepcopy(before)
        after["vulnerabilities"][0]["ratings"][0]["score"] = 9
        result = supply.diff(self.raw(before), self.raw(after))
        self.assertFalse(result["normalized_inventory_equal"])
        self.assertTrue(result["vulnerability_claims_changed"])

    def test_diff_invalid_or_over_limit_side_cannot_report_equality(self):
        with self.assertRaises(ValueError):
            supply.diff(self.raw(supply.sample()), b'{}')
        value = supply.sample()
        value["components"] *= 1000
        with self.assertRaises(ValueError):
            supply.diff(self.raw(supply.sample()), self.raw(value))

    def test_comparison_tool_sample_preserves_ids_and_reports_changed_version(self):
        bundle = supply.diff_sample()
        raw = json.dumps(bundle, indent=2).encode()
        result = supply.analyze_diff(raw)
        self.assertEqual(result["embedded_document_encoding"], "canonical_json")
        self.assertEqual(result["changed_components"], [{"id": "library", "fields": ["version"]}])
        self.assertFalse(result["normalized_inventory_equal"])
        self.assertEqual(result["left_sha256"], self.analyze(bundle["left"])["source_sha256"])
        self.assertEqual(result["source_bundle_sha256"], __import__("hashlib").sha256(raw).hexdigest())

    def test_comparison_tool_identical_documents_are_complete_and_equal(self):
        sample = supply.sample()
        result = supply.analyze_diff(self.raw({"left": sample, "right": sample}))
        self.assertTrue(result["complete"])
        self.assertTrue(result["normalized_inventory_equal"])
        self.assertEqual(result["changed_components"], [])
        self.assertEqual(result["left_sha256"], result["right_sha256"])

    def test_comparison_tool_rejects_extra_fields_wrong_types_and_oversized_bundle(self):
        for bundle in [{"left": supply.sample()}, {"left": [], "right": supply.sample()},
                       {"left": supply.sample(), "right": supply.sample(), "command": "never-run"}]:
            with self.subTest(bundle=bundle), self.assertRaises(ValueError):
                supply.analyze_diff(self.raw(bundle))
        with patch.dict(supply.LIMITS, input_bytes=100), self.assertRaises(ValueError):
            supply.analyze_diff(self.raw(supply.diff_sample()))

    def test_comparison_tool_can_match_equivalent_documented_cross_format_inventory(self):
        spdx = self.spdx()
        cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6",
               "components": [{"bom-ref": "SPDXRef-app", "name": "app", "version": "1.0",
                               "licenses": [{"license": {"id": "MIT"}}],
                               "purl": "pkg:generic/app@1.0", "hashes": [{"alg": "SHA-256", "content": "a" * 64}]},
                              {"bom-ref": "SPDXRef-lib", "name": "lib", "version": "2.0", "licenses": [{"license": {"id": "Apache-2.0"}}]}],
               "dependencies": [{"ref": "SPDXRef-app", "dependsOn": ["SPDXRef-lib"]}]}
        result = supply.analyze_diff(self.raw({"left": spdx, "right": cdx}))
        self.assertEqual(result["left_format"], "SPDX-2.3")
        self.assertEqual(result["right_format"], "CycloneDX-1.6")
        self.assertTrue(result["normalized_inventory_equal"])
        self.assertNotEqual(result["left_sha256"], result["right_sha256"])

    def test_registered_inventory_tool_runs_in_real_resource_bounded_worker(self):
        from cyber_platform import worker
        result = worker.analyze("supply-chain", self.raw(supply.sample()), timeout=3)
        self.assertEqual(result["component_count"], 2)
        self.assertEqual(result["summary"]["dependencies"], 1)
        self.assertFalse(result["network"])

    def test_registered_comparison_tool_uses_real_worker_without_truncating_changes(self):
        from cyber_platform import worker
        result = worker.analyze("supply-chain-diff", self.raw(supply.diff_sample()), timeout=3)
        self.assertTrue(result["complete"])
        self.assertEqual(result["changed_components"], [{"id": "library", "fields": ["version"]}])
        self.assertFalse(result["normalized_inventory_equal"])

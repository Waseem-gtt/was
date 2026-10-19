"""Strict adapters preserve evidence and reject the entire invalid batch."""
import hashlib
import json
import unittest
from cyber_platform import event_adapters as ea, tools, worker


class EventAdapterTests(unittest.TestCase):
    def sample(self, adapter):
        return next(x["example_content"] for x in ea.catalog() if x["id"] == adapter)

    def test_catalog_examples_and_input_provenance(self):
        for entry in ea.catalog():
            with self.subTest(adapter=entry["id"]):
                result = ea.normalize(entry["id"], entry["example_content"])
                self.assertEqual(result["count"], 1)
                self.assertEqual(result["input_sha256"], hashlib.sha256(entry["example_content"].encode()).hexdigest())
                self.assertEqual(result["schema"], "was.event/1")

    def test_windows_flat_original_and_no_guessed_semantics(self):
        original = {"time": "2026-01-01T01:00:00+01:00", "event_id": 4625, "actor": "علي"}
        event = ea.normalize("windows-json", json.dumps([original]))["events"][0]
        self.assertEqual(event["original"], original)
        self.assertEqual((event["action"], event["outcome"]), ("unknown", "unknown"))
        self.assertEqual(event["time"], original["time"])

    def test_windows_system_subset(self):
        original = {"System": {"EventID": 4624, "TimeCreated": {"SystemTime": "2026-01-01T00:00:00Z"}, "Computer": "demo", "Provider": "test"}, "EventData": {"TargetUserName": "user", "Other": "kept"}}
        event = ea.normalize("windows-json", json.dumps([original]))["events"][0]
        self.assertEqual(event["original"], original)
        self.assertEqual(event["actor"], "user")
        self.assertEqual(event["host"], "demo")
        self.assertEqual(event["outcome"], "unknown")

    def test_windows_reject_shapes_and_invalid_second_record(self):
        valid = {"time": "2026-01-01T00:00:00Z", "event_id": 1}
        for invalid in ({**valid, "event_id": True}, {**valid, "event_id": 65536}, {**valid, "unexpected": 1}, {**valid, "actor": 5}, {**valid, "outcome": "attack"}, {"System": {"EventID": 1, "TimeCreated": "date"}}, []):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "Record 2"):
                ea.normalize("windows-json", json.dumps([valid, invalid]))

    def test_json_strict_and_empty(self):
        for invalid in ('[]', '{}', '[{"time":"unknown","event_id":1,"event_id":2}]', '[NaN]', '[Infinity]', '[1e999]', '[null]', 'null'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ea.normalize("windows-json", invalid)

    def test_timestamps_require_valid_date_and_offset(self):
        for timestamp in ("2026-02-30T00:00:00Z", "2026-01-01T00:00:00", "2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+01:60", "2026-01-01T00:00:60Z", 123):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(ValueError, "Record 1"):
                ea.normalize("windows-json", json.dumps([{"time": timestamp, "event_id": 1}]))

    def test_syslog_multiple_records_structured_quotes_and_nil(self):
        line = '<165>1 2026-01-01T00:00:00.123456Z host app 99 ID [first a="quote\\\" slash\\\\ end\\]"][second b="ok"] message <safe>'
        result = ea.normalize("syslog-rfc5424", line + '\n<0>1 - - - - - -\n')
        event = result["events"][0]
        self.assertEqual(event["original"], line)
        self.assertEqual(event["facility"], 20)
        self.assertEqual(event["severity"], 5)
        self.assertEqual(event["message"], "message <safe>")
        self.assertEqual(event["outcome"], "unknown")
        self.assertEqual(result["events"][1]["time"], "unknown")

    def test_syslog_reject_malformed_headers_and_sd(self):
        tails = ('[x a="unclosed]', '[x a="bad\\q"]', '[x a="bad]value"]', '[x a="1" a="2"]', '[x][x]', '[x]suffix', '', '[x a="1"b="2"]')
        for tail in tails:
            with self.subTest(tail=tail), self.assertRaisesRegex(ValueError, "Record 1"):
                ea.normalize("syslog-rfc5424", '<34>1 - host app 1 ID ' + tail)
        with self.assertRaises(ValueError):
            ea.normalize("syslog-rfc5424", '<34>1 unknown host app 1 ID -')
        for header in ('<192>1', '<01>1', '<3>2', '<-1>1'):
            with self.subTest(header=header), self.assertRaises(ValueError):
                ea.normalize("syslog-rfc5424", header + ' - host app 1 ID -')

    def test_flow_original_and_explicit_outcome(self):
        content = 'time,source,destination,protocol,bytes,action,outcome\n2026-01-01T00:00:00Z,2001:db8::1,192.0.2.1,TCP,0,"allow, logged",success\n'
        event = ea.normalize("flows-csv", content)["events"][0]
        self.assertEqual(event["original"]["bytes"], "0")
        self.assertEqual(event["bytes"], 0)
        self.assertEqual(event["action"], "allow, logged")
        self.assertEqual(event["outcome"], "success")

    def test_flow_strict_csv(self):
        header = 'time,source,destination,protocol,bytes\n'
        for content in (header, header+'unknown,192.0.2.1,192.0.2.2,TCP,-1', header+'unknown,localhost,192.0.2.2,TCP,1', header+'unknown,192.0.2.1,192.0.2.2,TCP,18446744073709551616', header+'unknown,192.0.2.1,192.0.2.2,TCP,1,extra', header+'unknown,192.0.2.1', header+'"unclosed', 'time,time,source,destination,protocol,bytes\n', 'time,source,destination,protocol,bytes,extra\n'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                ea.normalize("flows-csv", content)

    def test_limits_and_invalid_content(self):
        valid = {"time": "unknown", "event_id": 1}
        for adapter, content in (("other", "x"), ("windows-json", None), ("windows-json", ""), ("windows-json", "x"*(ea.MAX_BYTES+1)), ("windows-json", json.dumps([valid]*1001)), ("windows-json", json.dumps([{**valid, "actor": "a"*8192}])), ("windows-json", "\ud800")):
            with self.subTest(adapter=adapter), self.assertRaises(ValueError):
                ea.normalize(adapter, content)
        self.assertEqual(ea.normalize("windows-json", json.dumps([valid]*1000))["count"], 1000)

    def test_envelope_strict_and_legacy_unchanged(self):
        original = [{"user": "demo", "outcome": "failure", "other": "preserved"}]
        self.assertEqual(tools.events(json.dumps(original).encode()), {"schema": "was.event/1", "events": [{"time": "unknown", "actor": "demo", "action": "unknown", "outcome": "failure", "original": original[0]}], "count": 1, "failed": 1, "limitations": "ليس محول OCSF كاملًا"})
        for envelope in ({"adapter": "windows-json"}, {"adapter": "windows-json", "content": "[]", "extra": 1}):
            with self.assertRaises(ValueError):
                tools.events(json.dumps(envelope).encode())
        with self.assertRaises(ValueError):
            tools.events(b'{"adapter":"windows-json","adapter":"windows-json","content":"[]"}')

    def test_spawned_worker_accepts_and_rejects(self):
        payload = {"adapter": "flows-csv", "content": self.sample("flows-csv")}
        result = worker.analyze("events", json.dumps(payload).encode())
        self.assertEqual(result["count"], 1)
        payload["content"] += 'invalid\n'
        with self.assertRaisesRegex(ValueError, "Record 2"):
            worker.analyze("events", json.dumps(payload).encode())


if __name__ == '__main__':
    unittest.main()

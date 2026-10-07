import os
import tempfile
import unittest
from pathlib import Path

from sentinel_collector.state import Position, StateStore
from sentinel_collector.tailer import Tailer


class TailerCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "alert_json.txt"

    def tearDown(self):
        self.dir.cleanup()

    def write(self, data: bytes, mode="ab"):
        with open(self.path, mode) as f:
            f.write(data)

    def tailer(self, start_at="beginning", position=None, max_line=1000):
        return Tailer(str(self.path), start_at, max_line, position)

    def drain(self, t):
        b = t.peek()
        if b is not None:
            t.commit(b.position)
        return b.lines if b else None


class ReadingTests(TailerCase):
    def test_reads_complete_lines_and_waits_for_a_partial_one(self):
        self.write(b'{"a":1}\n{"a":2}\n{"a":')
        t = self.tailer()
        self.assertEqual(self.drain(t), ['{"a":1}', '{"a":2}'])
        self.assertEqual(self.drain(t), [])  # the unfinished line is not consumed
        self.write(b'3}\n')
        self.assertEqual(self.drain(t), ['{"a":3}'])

    def test_start_at_end_ignores_history_and_picks_up_new_lines(self):
        self.write(b"old1\nold2\n")
        t = self.tailer(start_at="end")
        self.assertEqual(self.drain(t), [])
        self.write(b"new\n")
        self.assertEqual(self.drain(t), ["new"])

    def test_start_at_beginning_reads_history(self):
        self.write(b"old1\nold2\n")
        self.assertEqual(self.drain(self.tailer("beginning")), ["old1", "old2"])

    def test_windows_line_endings_blank_lines_and_bad_utf8(self):
        self.write(b"one\r\n\r\n   \r\ntw\xffo\r\n")
        lines = self.drain(self.tailer())
        self.assertEqual(lines[0], "one")
        self.assertEqual(len(lines), 2)
        self.assertIn("tw", lines[1])

    def test_peek_does_not_advance_until_commit(self):
        self.write(b"a\nb\n")
        t = self.tailer()
        self.assertEqual(t.peek().lines, ["a", "b"])
        self.assertEqual(t.peek().lines, ["a", "b"])  # a failed send is simply read again
        t.commit(t.peek().position)
        self.assertEqual(t.peek().lines, [])

    def test_missing_file_is_not_an_error(self):
        t = self.tailer()
        self.assertIsNone(t.peek())
        self.write(b"x\n")
        self.assertEqual(self.drain(t), ["x"])

    def test_the_file_is_never_held_open_between_polls(self):
        self.write(b"a\n")
        t = self.tailer()
        self.drain(t)
        os.replace(self.path, self.path.with_name("moved.txt"))  # would fail on Windows if a handle were kept
        self.assertTrue(self.path.with_name("moved.txt").exists())


class RotationTests(TailerCase):
    def test_rotation_by_rename_reads_the_new_file_from_its_start(self):
        self.write(b"a\nb\n")
        t = self.tailer()
        self.drain(t)
        os.rename(self.path, self.path.with_name("alert_json.txt.1"))
        self.write(b"c\nd\n", "wb")
        self.assertEqual(self.drain(t), ["c", "d"])

    def test_truncation_restarts_from_the_beginning(self):
        self.write(b"aaaa\nbbbb\ncccc\n")
        t = self.tailer()
        self.drain(t)
        self.write(b"z\n", "wb")
        self.assertEqual(self.drain(t), ["z"])

    def test_replaced_file_with_the_same_size_is_still_detected(self):
        self.write(b"1111\n")
        t = self.tailer()
        self.drain(t)
        os.remove(self.path)
        self.write(b"2222\n", "wb")
        self.assertEqual(self.drain(t), ["2222"])


class LimitTests(TailerCase):
    def test_overlong_lines_are_skipped_and_counted_but_neighbours_survive(self):
        self.write(b"ok1\n" + b"x" * 500 + b"\nok2\n")
        b = self.tailer(max_line=100).peek()
        self.assertEqual(b.lines, ["ok1", "ok2"])
        self.assertEqual(b.skipped_oversize, 1)

    def test_a_runaway_line_with_no_newline_cannot_exhaust_memory(self):
        self.write(b"y" * 5000)
        t = self.tailer(max_line=1000)
        b = t.peek()
        self.assertEqual((b.lines, b.skipped_oversize), ([], 1))
        t.commit(b.position)
        self.write(b"tail\nok\n")
        self.assertIn("ok", self.drain(t))

    def test_polls_are_bounded(self):
        from sentinel_collector import tailer as mod

        self.write(b"l\n" * (mod.MAX_LINES_PER_POLL + 10))
        t = self.tailer()
        first = t.peek()
        self.assertEqual(len(first.lines), mod.MAX_LINES_PER_POLL)
        t.commit(first.position)
        self.assertEqual(len(t.peek().lines), 10)


class StateTests(TailerCase):
    def store(self):
        return StateStore(Path(self.dir.name) / "state" / "s.json", str(self.path))

    def test_restart_resumes_exactly_where_it_stopped(self):
        self.write(b"a\nb\nc\n")
        t = self.tailer()
        b = t.peek()
        t.commit(b.position)
        self.store().save(b.position)
        self.write(b"d\n")
        t2 = self.tailer("end", self.store().load())
        self.assertEqual(self.drain(t2), ["d"])

    def test_uncommitted_work_is_replayed_after_a_crash(self):
        self.write(b"a\nb\n")
        self.tailer().peek()  # read but never saved: simulates dying mid-send
        t2 = self.tailer("end", self.store().load())
        self.assertEqual(t2.peek().lines, [])  # no state + start_at=end; with state saved earlier it would resume
        t3 = self.tailer("beginning", None)
        self.assertEqual(t3.peek().lines, ["a", "b"])

    def test_corrupt_or_foreign_state_is_ignored_safely(self):
        s = self.store()
        s.path.parent.mkdir(parents=True)
        for junk in ("", "{not json", "[]", '{"file_id": 1}', '{"file_id":"x","offset":"NaN","alert_file":"%s"}' % self.path):
            s.path.write_text(junk)
            self.assertIsNone(s.load(), junk)
        s.save(Position("1:2", 5))
        self.assertEqual(s.load(), Position("1:2", 5))
        self.assertIsNone(StateStore(s.path, "/some/other/file").load())

    def test_save_is_atomic_no_temp_file_left_behind(self):
        s = self.store()
        s.save(Position("1:2", 5))
        s.save(Position("1:2", 9))
        self.assertEqual(sorted(p.name for p in s.path.parent.iterdir()), ["s.json"])


if __name__ == "__main__":
    unittest.main()

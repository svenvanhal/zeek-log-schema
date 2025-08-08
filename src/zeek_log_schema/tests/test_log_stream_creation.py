import unittest
from pathlib import Path

from zeek_log_schema.zeek import ZeekScriptParser


class TestLogStreamCreation(unittest.TestCase):
    def test_log_stream_creation(self):
        parser = ZeekScriptParser(
            Path("res/00_log_stream.zeek"), relative_to_scripts=False
        )
        parser.parse()


if __name__ == "__main__":
    unittest.main()

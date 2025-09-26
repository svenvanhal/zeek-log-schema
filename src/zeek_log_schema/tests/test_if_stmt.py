import unittest
from pathlib import Path

from zeek_log_schema.zeek import ZeekScriptParser


class ZeekIfStmtParsingTest(unittest.TestCase):
    def test_if_stmt(self):
        parser = ZeekScriptParser(
            Path("res/03_if_stmt.zeek"), relative_to_scripts=False
        )
        parser.parse()


if __name__ == "__main__":
    unittest.main()

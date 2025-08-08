import unittest
from pathlib import Path

from zeek_log_schema.zeek import ZeekScriptParser


class MyTestCase(unittest.TestCase):
    def test_record_decl(self):
        parser = ZeekScriptParser(
            Path("res/01_record_decl.zeek"), relative_to_scripts=False
        )
        parser.parse()

    def test_record_redef(self):
        parser = ZeekScriptParser(
            Path("res/02_test_record_redef.zeek"), relative_to_scripts=False
        )
        parser.parse()


if __name__ == "__main__":
    unittest.main()

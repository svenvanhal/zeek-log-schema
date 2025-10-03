import unittest
from pathlib import Path

from zeek_log_schema.zeek import ZeekScriptParser


class RedefAmpLogTest(unittest.TestCase):
    def test_record_decl(self):
        parser = ZeekScriptParser(
            Path("res/04_redef_amp_log.zeek"), relative_to_scripts=False
        )
        parser.parse()


if __name__ == "__main__":
    unittest.main()

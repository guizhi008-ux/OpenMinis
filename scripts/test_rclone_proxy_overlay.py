import importlib.util
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('overlay', pathlib.Path(__file__).with_name('rclone_proxy_overlay.py'))
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)


class OverlayTests(unittest.TestCase):
    def test_hash_mismatch_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / 'dialer.go'
            source.write_text('changed upstream')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                overlay.generate(source, root / 'output')
            self.assertFalse((root / 'output').exists())


if __name__ == '__main__':
    unittest.main()

import pathlib, tempfile, unittest
from gate import Rejected, load_json, read_regular, verify_signature

class GateTests(unittest.TestCase):
    def test_duplicate_json_rejected(self):
        with self.assertRaises(Rejected): load_json('{"builder":"a","builder":"b"}')
    def test_symlink_and_limit_reject(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d); (p/'file').write_text('123'); (p/'link').symlink_to(p/'file')
            with self.assertRaises(Rejected): read_regular(p/'link',10)
            with self.assertRaises(Rejected): read_regular(p/'file',2)
    def test_verifier_unavailable_and_failure(self):
        for exe in ['/does-not-exist','/bin/false']:
            with self.assertRaises(Rejected): verify_signature(exe,'a','b','c',1)
    def test_invalid_json_reject(self):
        with self.assertRaises(Rejected): load_json('{')

if __name__=='__main__': unittest.main()

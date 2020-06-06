#!/usr/bin/python3
import subprocess
import unittest
import tempfile
import os

COMMAND = ["valgrind", "./rhsplit"]


class RHSplitTests(unittest.TestCase):
    def test_nonexistent(self):
        with tempfile.TemporaryDirectory() as temp_path:
            data_path = os.path.join(temp_path, "data")
            content = os.urandom(1024 * 1024 * 100)

            with self.assertRaises(subprocess.CalledProcessError):
                subprocess.check_output(COMMAND + [data_path], input=content)

    def test_unexpected_file(self):
        with tempfile.TemporaryDirectory() as temp_path:
            data_path = os.path.join(temp_path, "data")
            content = os.urandom(1024 * 1024 * 100)

            os.mkdir(data_path)
            with open(os.path.join(data_path, "unexpected"), "wb") as fp:
                pass

            with self.assertRaises(subprocess.CalledProcessError):
                subprocess.check_output(COMMAND + [data_path], input=content)

    def test_pack_and_unpack(self):
        with tempfile.TemporaryDirectory() as temp_path:
            data_path = os.path.join(temp_path, "data")
            content = os.urandom(1024 * 1024 * 100)

            os.mkdir(data_path)

            subprocess.check_output(COMMAND + [data_path], input=content)
            old_files = set(os.listdir(data_path))
            self.assertIn("unpack", old_files)

            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)

            content = (
                content[: len(content) // 2]
                + os.urandom(4096)
                + content[len(content) // 2 :]
            )
            subprocess.check_output(COMMAND + [data_path], input=content)
            new_files = set(os.listdir(data_path))
            self.assertIn("unpack", new_files)

            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)

            differences = old_files ^ new_files
            self.assertLessEqual(len(differences), 4)

            any_file = next(iter(list(differences & new_files)))
            with open(os.path.join(data_path, any_file), "ab+") as fp:
                fp.write(b"GARBAGE")

            subprocess.check_output(COMMAND + [data_path], input=content)
            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)


if __name__ == "__main__":
    unittest.main()

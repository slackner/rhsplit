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

    def test_empty(self):
        with tempfile.TemporaryDirectory() as temp_path:
            data_path = os.path.join(temp_path, "data")
            content = b""

            os.mkdir(data_path)

            subprocess.check_output(COMMAND + [data_path], input=content)
            files = set(os.listdir(data_path))
            self.assertEqual(files, set(["unpack"]))

            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)

    def test_single_block(self):
        with tempfile.TemporaryDirectory() as temp_path:
            data_path = os.path.join(temp_path, "data")
            content = os.urandom(1024 * 1024 * 5)

            os.mkdir(data_path)

            subprocess.check_output(COMMAND + [data_path], input=content)
            files = set(os.listdir(data_path))
            self.assertIn("unpack", files)
            self.assertGreater(len(files), 2)

            file_name = None
            with open(os.path.join(data_path, "unpack"), "r") as fp:
                for line in fp:
                    line = line.rstrip()
                    if line.startswith("cat "):
                        file_name = line[4:]
                        break

            self.assertNotEqual(file_name, None)
            self.assertTrue(os.path.exists(os.path.join(data_path, file_name)))

            file_size = os.stat(os.path.join(data_path, file_name)).st_size
            content = content[:file_size]

            subprocess.check_output(COMMAND + [data_path], input=content)
            files = set(os.listdir(data_path))
            self.assertEqual(files, set(["unpack", file_name]))

            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)

    def test_pack_and_unpack(self):
        with tempfile.TemporaryDirectory() as temp_path:
            data_path = os.path.join(temp_path, "data")
            content = os.urandom(1024 * 1024 * 100)

            os.mkdir(data_path)

            # Test splitting a large file
            subprocess.check_output(COMMAND + [data_path], input=content)
            old_files = set(os.listdir(data_path))
            self.assertIn("unpack", old_files)
            self.assertGreater(len(old_files), 10)

            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)

            # Test inserting content in the middle
            content = (
                content[: len(content) // 2]
                + os.urandom(4096)
                + content[len(content) // 2 :]
            )
            subprocess.check_output(COMMAND + [data_path], input=content)
            new_files = set(os.listdir(data_path))
            self.assertIn("unpack", new_files)
            self.assertLessEqual(len(old_files ^ new_files), 4)

            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)

            # Test what happens if a file is corrupted
            any_file = next(iter(list((old_files ^ new_files) & new_files)))
            with open(os.path.join(data_path, any_file), "ab+") as fp:
                fp.write(b"GARBAGE")

            subprocess.check_output(COMMAND + [data_path], input=content)
            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)

            # Test truncating the existing file
            old_files = new_files
            content = content[: len(content) // 2]
            subprocess.check_output(COMMAND + [data_path], input=content)
            new_files = set(os.listdir(data_path))
            self.assertIn("unpack", new_files)
            self.assertLess(len(new_files), len(old_files))

            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)


if __name__ == "__main__":
    unittest.main()

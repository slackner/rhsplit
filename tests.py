#!/usr/bin/python3
import subprocess
import unittest
import tempfile
import hashlib
import os

COMMAND = ["valgrind", "--leak-check=full", "--error-exitcode=1", "./rhsplit"]


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

    def test_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_path:
            data_path = os.path.join(temp_path, "data")

            # We use pbkdf2 to generate some deterministic but random looking content.
            content = hashlib.pbkdf2_hmac(
                "sha256", b"PASSWORD", b"SALT", 10, dklen=1024 * 1024 * 10
            )

            os.mkdir(data_path)

            expected = [
                "033c7eb383c672f5a23c64199efff588f532e23c9d5cab8dfde4b095813a94bf",
                "29606970424baa0d5fbc8e7ae3e182eaae5166d6d387afb1aa771b97e7809c1b",
                "64da053347d9606d050e4818ff25fa7e4a78460f247a42c95e5e2b97097e3744",
                "8190655075d5de85e6b061f16a45a659275b14aa07b1dc19704d4ef13e10e011",
                "9c3fb2cd8142593d68615d9fa2475ef61c4e9b538fd9640ab8d410636dc2b07c",
                "a3ed7632d7d307bd6f240acfced9c6ab5125725a65504cd2f1ca5282797d741b",
                "b10b20d787dcede6897ac273f54aa68a664792153348d5c8b170821be191c4e1",
                "bd10d800203365a897541980b2b1cf123461d6e57cec503b9890286ec714eefc",
                "c491bfb130da5ce81c918abc4a9cf430cfcb50db02fd7dd322309c4053be42bc",
                "cfa406a487faf87c73b646c3dc0d72a08ffbdf32a2e4815791d8a1b1a4ccf5e0",
                "cffa95a3896f2dee7357f9737dcb2130dea79b90729855b557d145553c550b27",
                "e1e8c3092f7527b533e25b2d4f19a6aee806233db3f5faf91baf616ecefbe70c",
                "unpack",
            ]

            subprocess.check_output(COMMAND + [data_path], input=content)
            files = set(os.listdir(data_path))
            self.assertEqual(files, set(expected))

            output = subprocess.check_output([os.path.join(data_path, "unpack")])
            self.assertEqual(output, content)


if __name__ == "__main__":
    unittest.main()

import os.path
import io
import subprocess
from concurrent.futures import ThreadPoolExecutor
import enum
import re
import json
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path, data):
    with open(path, "wb") as f:
        return f.write(data)


def read_text(path):
    with open(path, "r") as f:
        return f.read()


def write_text(path, data):
    with open(path, "w") as f:
        return f.write(data)


def read_json(path):
    with open(path, "r") as f:
        return json.load(f)


def request_bytes(url, headers):
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.content


def ensure_download(url, headers, path):
    if os.path.exists(path):
        print("Target already exists:", path)
    else:
        data = request_bytes(url, headers)
        write_bytes(path, data)


def decrypt_aes(key, iv, data):
    algo = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(algo, mode)
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    return data


def ensure_decrypt(key, iv, enc_path, dec_path):
    if os.path.exists(dec_path):
        print("Target already exists:", dec_path)
    else:
        enc = read_bytes(enc_path)
        dec = decrypt_aes(key, iv, enc)
        write_bytes(dec_path, dec)


def parse_simple_kv_list(text: str):
    """Parse simple key-value list string, like: a=1,b=2,c=3.
    Repect \"XXX\" as XXX.
    """
    d = {}
    for kv in text.split(","):
        kv = kv.strip()
        k, v = kv.split("=", 1)
        k, v = k.strip(), v.strip()
        match_result = re.match('^"(.*)"$', v)
        if match_result is not None:
            v = match_result[1].strip()
        d[k] = v
    return d


class M3U8Parser:
    class Stage(enum.Enum):
        init = enum.auto()
        header_or_trunk_key_or_end = enum.auto()
        trunk_key_or_end = enum.auto()
        trunk_value = enum.auto()
        end = enum.auto()

    def __init__(self):
        self.stage = self.Stage.init
        self.headers = {}
        self.trunks = []

    @classmethod
    def parse(cls, text: str):
        parser = cls()
        for line in text.splitlines():
            parser.input(line.strip())
        if parser.stage is not parser.Stage.end:
            raise Exception("Parse not end", parser.stage)
        return parser.headers, parser.trunks

    def input(self, line: str):
        match self.stage:
            case self.Stage.init:
                self.input_init(line)
            case self.Stage.header_or_trunk_key_or_end:
                self.input_header_or_trunk_key_or_end(line)
            case self.Stage.trunk_key_or_end:
                self.input_trunk_key_or_end(line)
            case self.Stage.trunk_value:
                self.input_trunk_value(line)
            case _:
                raise Exception("Invalid stage", self.stage)

    def input_init(self, line: str):
        if line == "#EXTM3U":
            self.stage = self.Stage.header_or_trunk_key_or_end
        else:
            raise Exception("Invalid init", line)

    def input_header_or_trunk_key_or_end(self, line: str):
        if line == "#EXT-X-ENDLIST":
            self.stage = self.Stage.end
        elif line.startswith("#EXT-X"):
            k, v = line.split(":", 1)
            self.headers[k] = v
        elif line.startswith("#EXTINF"):
            self.stage = self.Stage.trunk_value
        else:
            raise Exception("Invalid header or trunk key or end", line)

    def input_trunk_key_or_end(self, line: str):
        if line == "#EXT-X-ENDLIST":
            self.stage = self.Stage.end
        elif line.startswith("#EXTINF"):
            self.stage = self.Stage.trunk_value
        else:
            raise Exception("Invalid trunk key or end", line)

    def input_trunk_value(self, line: str):
        self.trunks.append(line)
        self.stage = self.Stage.trunk_key_or_end


class M3U8Downloader:
    def __init__(
        self,
        url,
        headers,
        download_path="download/",
        index_name="_index.txt",
        output_name="_output.mp4",
        async_max_workers=10,
        check_mode=False,
    ):
        self.base_url, self.m3u8_meta = url.rsplit("/", 1)
        self.base_url += "/"
        self.headers = headers
        self.download_path = download_path
        self.index_name = index_name
        self.output_name = output_name
        self.async_max_workers = async_max_workers
        self.check_mode = check_mode

    @classmethod
    def from_json(cls, json_path, **kwargs):
        params = read_json(json_path)
        url = params["url"]
        headers = params["headers"]
        return cls(url, headers, **kwargs)

    def read_bytes(self, name):
        path = self.download_path + name
        return read_bytes(path)

    def read_text(self, name):
        path = self.download_path + name
        return read_text(path)

    def ensure_download(self, name):
        path = self.download_path + name
        if self.check_mode:
            if not os.path.exists(path):
                raise Exception("Download target not exists:", name)
        else:
            url = self.base_url + name
            ensure_download(url, self.headers, path)

    def ensure_decrypt(self, name):
        enc_path = self.download_path + name
        dec_path = enc_path + "._decrypt.ts"
        if self.check_mode:
            if not os.path.exists(dec_path):
                raise Exception("Decrypt target not exists:", name)
        else:
            ensure_decrypt(self.key, self.iv, enc_path, dec_path)

    def fetch_meta(self):
        print("Fetch m3u8 meta...")
        self.ensure_download(self.m3u8_meta)
        self.m3u8_meta = self.read_text(self.m3u8_meta)
        self.m3u8_headers, self.m3u8_trunks = M3U8Parser.parse(self.m3u8_meta)
        if "#EXT-X-KEY" not in self.m3u8_headers:
            self.crypt_mode = False
        else:
            self.crypt_mode = True
            self.fetch_crypt_key()

    def fetch_crypt_key(self):
        self.m3u8_key_meta = parse_simple_kv_list(self.m3u8_headers["#EXT-X-KEY"])
        if not self.m3u8_key_meta["METHOD"].startswith("AES-"):
            raise Exception("Invalid method", self.m3u8_key_meta)
        if not self.m3u8_key_meta["IV"].startswith("0x"):
            raise Exception("Invalid iv", self.m3u8_key_meta)
        self.iv = bytes.fromhex(self.m3u8_key_meta["IV"][2:])
        print("Fetch crypt key...")
        self.ensure_download(self.m3u8_key_meta["URI"])
        self.key = self.read_bytes(self.m3u8_key_meta["URI"])

    def fetch_trunk(self, i):
        trunks = self.m3u8_trunks
        trunk = trunks[i]
        print(f"Fetch trunk {i + 1}/{len(trunks)}...")
        self.ensure_download(trunk)
        if self.crypt_mode:
            self.ensure_decrypt(trunk)

    def fetch_trunks(self):
        print("Fetch trunks...")
        for i in range(len(self.m3u8_trunks)):
            self.fetch_trunk(i)

    def fetch_trunks_async(self):
        print("Fetch trunks...")
        with ThreadPoolExecutor(max_workers=self.async_max_workers) as executor:
            executor.map(self.fetch_trunk, range(len(self.m3u8_trunks)))

    def fetch(self):
        self.fetch_meta()
        self.fetch_trunks()

    def fetch_async(self):
        self.fetch_meta()
        self.fetch_trunks_async()

    def gen_index(self):
        print("Generate index...")
        sio = io.StringIO()
        for trunk in self.m3u8_trunks:
            if not self.crypt_mode:
                name = trunk
            else:
                name = trunk + "._decrypt.ts"
            print(f"file '{name}'", file=sio)
        write_text(self.download_path + self.index_name, sio.getvalue())

    def ffmpeg_concat(self):
        print("Concat videos...")
        subprocess.run(
            [
                "ffmpeg",
                "-f",
                "concat",
                "-i",
                self.index_name,
                "-c",
                "copy",
                self.output_name,
            ],
            cwd=self.download_path,
        )

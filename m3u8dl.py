import os.path
import re
import json
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def request_bytes(url, headers):
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.content


def ensure_download(url, headers, path):
    if os.path.exists(path):
        print("Target already exists:", path)
    else:
        data = request_bytes(url, headers)
        with open(path, "wb") as f:
            f.write(data)


def decrypt_aes(key, iv, data):
    algo = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(algo, mode)
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    return data


def parse_m3u8(text: str):
    stage = "init"
    headers = {}
    trunks = []
    for line in text.splitlines():
        line = line.strip()
        if stage == "init":
            if line == "#EXTM3U":
                stage = "header-or-trunk-key-or-end"
            else:
                raise Exception("Invalid init", stage, line)
        elif stage == "header-or-trunk-key-or-end":
            if line == "#EXT-X-ENDLIST":
                stage = "end"
            elif line.startswith("#EXT-X"):
                k, v = line.split(":", 1)
                headers[k] = v
            elif line.startswith("#EXTINF"):
                stage = "trunk-value"
            else:
                raise Exception("Invalid header or trunk key or end", stage, line)
        elif stage == "trunk-key-or-end":
            if line == "#EXT-X-ENDLIST":
                stage = "end"
            elif line.startswith("#EXTINF"):
                stage = "trunk-value"
            else:
                raise Exception("Invalid trunk key or end", stage, line)
        elif stage == "trunk-value":
            trunks.append(line)
            stage = "trunk-key-or-end"
        else:
            raise Exception("Invalid stage", stage)
    if stage != "end":
        raise Exception("Parse not end", stage)
    return headers, trunks


class M3U8Downloader:
    def __init__(self, url, http_headers, download_path="download/", check_mode=False):
        base_url, m3u8 = url.rsplit("/", 1)
        self.base_url = base_url + "/"
        self.m3u8 = m3u8
        self.http_headers = http_headers
        self.download_path = download_path
        self.check_mode = check_mode

    @classmethod
    def from_json(cls, json_path, check_mode=False):
        with open(json_path, "r") as f:
            params = json.load(f)
        url = params["url"]
        headers = params["headers"]
        return cls(url, headers, check_mode=check_mode)

    def ensure_download(self, name):
        if self.check_mode:
            path = self.download_path + name
            if not os.path.exists(path):
                raise Exception("Target not exists:", name)
        else:
            url = self.base_url + name
            path = self.download_path + name
            ensure_download(url, self.http_headers, path)

    def read_bytes(self, name):
        path = self.download_path + name
        with open(path, "rb") as f:
            return f.read()

    def read_text(self, name):
        path = self.download_path + name
        with open(path, "r") as f:
            return f.read()

    def fetch_m3u8(self):
        print("Fetch m3u8...")
        self.ensure_download(self.m3u8)
        text = self.read_text(self.m3u8)
        self.m3u8_headers, self.m3u8_trunks = parse_m3u8(text)
        if "#EXT-X-KEY" not in self.m3u8_headers:
            self.crypt_mode = False
        else:
            self.crypt_mode = True
            key = self.m3u8_headers["#EXT-X-KEY"]
            crypt_method, key_uri, iv = key.split(",", 2)
            if not crypt_method.startswith("METHOD=AES-"):
                raise Exception("Invalid Method", crypt_method)
            match_result = re.match('^URI="(.*)"$', key_uri)
            if match_result is None:
                raise Exception("Invalid key uri", key_uri)
            self.key_uri = match_result[1]
            if not iv.startswith("IV=0x"):
                raise Exception("Invalid iv", iv)
            self.iv = bytes.fromhex(iv[5:])
            print("Fetch crypt key...")
            self.ensure_download(self.key_uri)
            self.key = self.read_bytes(self.key_uri)

    def fetch_trunks(self):
        print("Fetch trunks...")
        trunks = self.m3u8_trunks
        total = len(trunks)
        for i, trunk in enumerate(trunks):
            print(f"Fetch trunk {i}/{total}...")
            self.ensure_download(trunk)

    def fetch(self):
        self.fetch_m3u8()
        self.fetch_trunks()

    def decrypt_trunks(self):
        print("Decrypt trunks...")
        trunks = self.m3u8_trunks
        total = len(trunks)
        for i, trunk in enumerate(trunks):
            print(f"Decrypt trunk {i}/{total}...")
            path = self.download_path + trunk + "._decrypt.ts"
            if os.path.exists(path):
                print("Target already exists:", trunk)
            else:
                if os.path.exists(self.download_path + trunk):
                    enc = self.read_bytes(trunk)
                    dec = decrypt_aes(self.key, self.iv, enc)
                    with open(path, "wb") as f:
                        f.write(dec)
                else:
                    if self.check_mode:
                        raise Exception("Target not exists:", trunk)

    def gen_list(self):
        with open(self.decrypt_path + "_videos.txt", "w") as f:
            for trunk in self.m3u8_trunks:
                if not self.crypt_mode:
                    name = trunk
                else:
                    name = trunk + "._decrypt.ts"
                print(f"file '{name}'", file=f)

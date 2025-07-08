import os.path
import re
import json
from concurrent.futures import ThreadPoolExecutor
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


def parse_m3u8_key(text: str):
    key = {}
    for kv in text.split(","):
        kv = kv.strip()
        k, v = kv.split("=", 1)
        k, v = k.strip(), v.strip()
        match_result = re.match('^"(.*)"$', v)
        if match_result is not None:
            v = match_result[1].strip()
        key[k] = v
    return key


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
        params = read_json(json_path)
        url = params["url"]
        headers = params["headers"]
        return cls(url, headers, check_mode=check_mode)

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
            ensure_download(url, self.http_headers, path)

    def ensure_decrypt(self, name):
        if self.crypt_mode:
            enc_path = self.download_path + name
            dec_path = enc_path + "._decrypt.ts"
            if self.check_mode:
                if not os.path.exists(dec_path):
                    raise Exception("Decrypt target not exists:", name)
            else:
                ensure_decrypt(self.key, self.iv, enc_path, dec_path)

    def fetch_m3u8(self):
        print("Fetch m3u8...")
        self.ensure_download(self.m3u8)
        text = self.read_text(self.m3u8)
        self.m3u8_headers, self.m3u8_trunks = parse_m3u8(text)
        if "#EXT-X-KEY" not in self.m3u8_headers:
            self.crypt_mode = False
        else:
            self.crypt_mode = True
            self.m3u8_key = parse_m3u8_key(self.m3u8_headers["#EXT-X-KEY"])
            if not self.m3u8_key["METHOD"].startswith("AES-"):
                raise Exception("Invalid method", self.m3u8_key)
            if not self.m3u8_key["IV"].startswith("0x"):
                raise Exception("Invalid iv", self.m3u8_key)
            self.iv = bytes.fromhex(self.m3u8_key["IV"][2:])
            print("Fetch crypt key...")
            self.ensure_download(self.m3u8_key["URI"])
            self.key = self.read_bytes(self.m3u8_key["URI"])

    def fetch_trunk(self, trunk, i, total):
        print(f"Fetch trunk {i}/{total}...")
        self.ensure_download(trunk)
        self.ensure_decrypt(trunk)

    def fetch_trunks(self):
        print("Fetch trunks...")
        trunks = self.m3u8_trunks
        total = len(trunks)
        for i, trunk in enumerate(trunks):
            self.fetch_trunk(trunk, i, total)

    def fetch(self):
        self.fetch_m3u8()
        self.fetch_trunks()

    def fetch_trunks_async(self, max_workers=10):
        print("Fetch trunks...")
        trunks = self.m3u8_trunks
        total = len(trunks)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(lambda i: self.fetch_trunk(trunks[i], i, total), range(total))

    def fetch_async(self, max_workers=10):
        self.fetch_m3u8()
        self.fetch_trunks_async(max_workers=max_workers)

    def gen_list(self):
        with open(self.download_path + "_videos.txt", "w") as f:
            for trunk in self.m3u8_trunks:
                if not self.crypt_mode:
                    name = trunk
                else:
                    name = trunk + "._decrypt.ts"
                print(f"file '{name}'", file=f)

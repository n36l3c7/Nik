"""An SFTP server for the tests: a thread of this process, on the loopback, serving one folder.

It is paramiko's own server side with a folder of ``tmp_path`` behind it, so
the code under test speaks real SSH (the host key, the sign-in, the SFTP
requests) and nothing leaves the machine. ``drop_after`` cuts the connection
once that many bytes of a file were written, to try a resumed upload.
"""

from __future__ import annotations

import os
import socket
import threading
from pathlib import Path

import paramiko
from paramiko import SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_OK, SFTPAttributes, SFTPHandle, SFTPServer


class _Handle(SFTPHandle):
    def __init__(self, server: SftpDouble, flags: int = 0) -> None:
        super().__init__(flags)
        self._server = server

    def write(self, offset, data):
        server = self._server
        if server.drop_after is not None:
            server.written += len(data)
            if server.written >= server.drop_after:
                server.drop_after = None
                server.cut()
                return SFTP_FAILURE
        return super().write(offset, data)

    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))


class _Files(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, double: SftpDouble, **kwargs) -> None:
        super().__init__(server, *args, **kwargs)
        self._double = double

    def _real(self, path: str) -> str:
        root = self._double.root
        real = os.path.realpath(os.path.join(root, self.canonicalize(path).lstrip("/")))
        if os.path.commonpath([real, str(root)]) != str(root):
            raise PermissionError(path)
        return real

    def list_folder(self, path):
        try:
            real = self._real(path)
            found = []
            for name in os.listdir(real):
                attr = SFTPAttributes.from_stat(os.stat(os.path.join(real, name)))
                attr.filename = name
                found.append(attr)
            return found
        except OSError as error:
            return SFTPServer.convert_errno(error.errno)

    def stat(self, path):
        try:
            return SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as error:
            return SFTPServer.convert_errno(error.errno)

    lstat = stat

    def open(self, path, flags, attr):
        try:
            real = self._real(path)
            binary = getattr(os, "O_BINARY", 0)
            fd = os.open(real, flags | binary, 0o600)
        except OSError as error:
            return SFTPServer.convert_errno(error.errno)
        if flags & os.O_WRONLY:
            mode = "ab" if flags & os.O_APPEND else "wb"
        elif flags & os.O_RDWR:
            mode = "a+b" if flags & os.O_APPEND else "r+b"
        else:
            mode = "rb"
        try:
            handle_file = os.fdopen(fd, mode)
        except OSError as error:
            return SFTPServer.convert_errno(error.errno)
        handle = _Handle(self._double, flags)
        handle.filename = real
        handle.readfile = handle_file
        handle.writefile = handle_file
        return handle

    def remove(self, path):
        try:
            os.remove(self._real(path))
        except OSError as error:
            return SFTPServer.convert_errno(error.errno)
        return SFTP_OK

    def rename(self, oldpath, newpath):
        try:
            os.replace(self._real(oldpath), self._real(newpath))
        except OSError as error:
            return SFTPServer.convert_errno(error.errno)
        return SFTP_OK

    posix_rename = rename

    def mkdir(self, path, attr):
        try:
            os.mkdir(self._real(path))
        except OSError as error:
            return SFTPServer.convert_errno(error.errno)
        return SFTP_OK

    def rmdir(self, path):
        return SFTP_NO_SUCH_FILE


class _Gate(paramiko.ServerInterface):
    def __init__(self, double: SftpDouble) -> None:
        self._double = double

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        allowed = self._double.client_key
        same = allowed is not None and key.get_base64() == allowed.get_base64()
        return paramiko.AUTH_SUCCESSFUL if username == self._double.user and same else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        good = username == self._double.user and self._double.password and password == self._double.password
        return paramiko.AUTH_SUCCESSFUL if good else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SftpDouble:
    """``with SftpDouble(folder) as server``: ``server.port``, ``server.host_key``, ``server.client_pem``."""

    user = "nikbackup"

    def __init__(self, root: Path, password: str = "") -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        self.root = Path(os.path.realpath(root))
        self.root.mkdir(parents=True, exist_ok=True)
        self.password = password
        self.drop_after: int | None = None
        self.written = 0
        self.connections = 0

        def pem() -> str:
            key = ed25519.Ed25519PrivateKey.generate()
            return key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
            ).decode("ascii")

        import io

        self.host_pem, self.client_pem = pem(), pem()
        self.host_key = paramiko.Ed25519Key.from_private_key(io.StringIO(self.host_pem))
        self.client_key = paramiko.Ed25519Key.from_private_key(io.StringIO(self.client_pem))
        self._socket = socket.socket()
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(8)
        self.port = self._socket.getsockname()[1]
        self._transports: list[paramiko.Transport] = []
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def host_line(self) -> str:
        return f"{self.host_key.get_name()} {self.host_key.get_base64()}"

    def _serve(self) -> None:
        while not self._stopping.is_set():
            try:
                connection, _address = self._socket.accept()
            except OSError:
                return
            self.connections += 1
            transport = paramiko.Transport(connection)
            transport.add_server_key(self.host_key)
            transport.set_subsystem_handler("sftp", SFTPServer, _Files, double=self)
            try:
                transport.start_server(server=_Gate(self))
            except (paramiko.SSHException, EOFError, OSError):
                continue
            self._transports.append(transport)

    def cut(self) -> None:
        """Drop every connection, as a network that fails does."""
        for transport in self._transports:
            transport.close()
        self._transports.clear()

    def __enter__(self) -> SftpDouble:
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stopping.set()
        self.cut()
        self._socket.close()

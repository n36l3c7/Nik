# Fixtures of the evtx parser

`Application_no_crc32.evtx` is the only file here, and it is not made by Nik: it is a test log of the `evtx` crate
(Rust parser of Windows event logs, by Omer Ben-Amram), kept as it is.

* Source: <https://github.com/omerbenamram/evtx/blob/5d0a82b7b5a872fa9542b9b2473407ae697b2fec/samples/Application_no_crc32.evtx>
  (the file is unchanged since the commit that added it, a0ec4c41cdf7bc274d589aa6ee69b23e01148aa7, 2021-04-01).
* Licence: the repository `omerbenamram/evtx` is MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
* Size: 69,632 bytes (the 4 KiB file header and one 64 KiB chunk), 17 records of the Application log of a Windows
  machine; the file header carries the "no CRC32" flag, so its checksums mean nothing.
* SHA-256: `2b128dc61812123a34ab2808502c6d48a0db6018e6b21bfb4f0be12d6dad2596`

Nothing else is committed. `tests/test_evtx.py` makes its logs from this one at run time: it copies the chunk into a
log of several chunks (new record numbers, right checksums, an empty unused space) and damages that log in the ways
a real one is damaged. The logs are not kept.

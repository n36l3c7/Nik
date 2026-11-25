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

## `ntfs/mft-ntfsprogs.bin`

An `$MFT` (122,880 bytes, 120 entries of 1024 bytes) of a 64 MB NTFS volume written by another implementation than
Nik's reader: ntfs-3g 2022.10.3 (Debian 12 package `1:2022.10.3-1+deb12u4`: `mkfs.ntfs`, the `ntfs-3g` driver,
`ntfsinfo`, `ntfsls`). It holds only files invented for the test (names such as `big.bin`, `tiny.txt`, `Users\bob\...`;
content is random bytes or the word `hello`), so there is no licence question. It is used by
`tests/test_mft.py::test_a_table_written_by_ntfs_3g_is_read_as_ntfsinfo_reads_it`.

How it was made, in a throwaway `debian:12-slim` container (privileged, `/dev/fuse`), nothing of ntfs-3g is shipped:

1. `truncate -s 64M vol.img; mkfs.ntfs -F -Q -L TESTVOL vol.img`
2. `ntfscp` cannot make directories, delete or link, so the image was mounted inside the container
   (`ntfs-3g -o streams_interface=windows vol.img /mnt/v`) and a tree was made with `mkdir`, `cp`, `ln`, `rm`:
   `Users\bob\Documents` (a long name with a DOS short name set with `setfattr -n system.ntfs_dos_name`, and 40 files,
   so that the index is non-resident), `Users\bob\Downloads\setup.exe` with a `Zone.Identifier` stream, `ads_host.txt`
   with an alternate stream `secret` and a hard link `hardlink.txt`, `big.bin` (3,000,000 bytes, non-resident),
   `tiny.txt` (6 bytes, resident), two grown files, and in `Users\alice` four entries created and then deleted.
3. Unmounted. `ntfscat vol.img '$MFT'` gives the table with its fix-ups already undone (the sector ends hold the
   data, not the update sequence number), which is not what is on a disk: so the committed file is the table as
   stored, read from the image by the data run of entry 0 (cluster 4, 31 clusters of 4096 bytes, cut to the 122,880
   bytes entry 0 says).
4. What the file says was compared with `ntfsinfo -i N` for every entry and `ntfsls -l -R`
   (sequence, in use, hard links, the four `$STANDARD_INFORMATION` times, every `$FILE_NAME` with parent, namespace and
   times, size, streams, attribute list).
* SHA-256: `221c3732d8aa606820e0213fb7fae813b73abeaa5c837a1fefb5b2e9eb6a05aa`

The times are those of the container's clock (2026-11-25). ntfs-3g leaves the `$STANDARD_INFORMATION` times of `$MFT`
itself at zero and gives names the POSIX namespace, as the test records.

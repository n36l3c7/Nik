# Mail listener / sender

A mailbox to read over IMAP and a server to send through over SMTP. One
instance is one mailbox.

## Setting up an instance

- **To send**: the SMTP server, its port and security (STARTTLS on 587 is the
  usual one), and the sender address.
- **To read and to listen**: the IMAP server, its port and security (TLS on
  993), and the folder to watch (INBOX by default).
- The user name and the password are used for both. Many providers want an
  *application password* for IMAP and SMTP, not the password of the account.

Either half may be left empty: an instance with no IMAP server only sends, one
with no SMTP server only reads.

## The listener

Turn on *fetch* for the instance and each message that arrives in the folder
becomes an incident, through the mapper of the connector: the subject is its
name, the text its details. A message is told apart by its Message-ID.

## Commands

`send`, `reply`, `forward`, `search`, `get-message`, `move`, `mark-read`,
`mark-unread`, `delete`, `list-folders`. Those that send write only to
addresses whose domain the playbook may reach. `delete` cannot be taken back.

An attachment is described (name, type, size, SHA-256) and never opened.

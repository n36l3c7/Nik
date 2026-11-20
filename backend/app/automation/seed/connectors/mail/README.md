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

The message itself is kept as evidence: it becomes an e-mail of the incident,
analysed as an uploaded `.eml` is (headers, SPF/DKIM/DMARC, links,
attachments, verdict), and the Evidence tab shows it. A message Nik holds
already is not analysed twice. Nothing is kept for a message a pre-processing
rule dropped; one a rule linked to an incident there was becomes evidence of
that incident. A message above the size limit of an upload is not kept, and
the item says so.

## Commands

`send`, `reply`, `forward`, `search`, `get-message`, `get-attachments`, `move`,
`mark-read`, `mark-unread`, `delete`, `list-folders`. Those that send write
only to addresses whose domain the playbook may reach. `delete` cannot be
taken back.

An attachment is described (name, type, size, SHA-256) and never opened.

### get-attachments

Keeps what is attached to a message as files in Nik: each is stored under its
SHA-256 and analysed as an uploaded file is, never run. The files go in the
incident the run works on (or the one named in `incident`); with no incident
they are kept on their own. The command gives one entry for each attachment
(`name`, `type`, `size`, `sha256`, `artifact`, `linked`, `note`) and the list
of the ids in `artifacts`, for a loop to go over. An attachment that is empty,
that could not be read or that is above the size limit of a sample is listed
with a `note` and no `artifact`. A message above that limit is refused, and
fifty attachments at most are looked at.

### forward and reply: what is taken from the mailbox

`forward` reads the message in the mailbox and quotes it in the new one: its
subject, its sender, its recipients, its date and its text. None of that is
written in the node, so the data guard judges it when the message is read,
each part by what it is: the subject is an *e-mail subject*, the sender and
the recipients are *e-mail addresses*, the text is an *e-mail body*, and each
is also read as any text that leaves is (a private address in the text is an
internal address). A playbook forwards a message only when an admin opened
those classes for it. Otherwise the step fails, nothing is sent, and the step
says what was held.

A node set to send without what is held sends the message without the held
parts: a line of the quoted header says `(held back)`, the subject becomes
`Fwd: (subject held back)`, and the text is replaced by one line saying the
data guard held it back. The output `quoted_held` names what stayed
(`subject`, `from`, `to`, `text`).

`reply` quotes no text. It repeats the subject of the message it answers
(`Re: …`), which is judged as an *e-mail subject* in the same way; held and
dropped, the answer goes as `Re: (subject held back)`, still in its
conversation. The `Message-ID` it names to stay in the conversation is not
judged: it goes back only to the people the message was sent by and to.

A dry run does not read the mailbox, so it cannot say what would be held: its
step says that what is taken from the message is judged when the step runs.
Outside a playbook there is no guard, and neither command sends anything.

### forward with attachments

`forward` carries the attachments of the message when `attachments` is on. It
is off by default: a file that leaves Nik is judged by the data guard, and
*attachments* is a class no playbook sends unless an admin opened it for that
playbook. The guard judges each file by what it is, its name, its size and its
hash, without opening it: it is an attachment, its name is a file name, and a
file Nik holds as a sample is a sample. When something is held the step fails
and says what, in one sentence with what was held of the quoted message; a
node set to send without what is held sends the message without its files
and says how many stayed (`attachments_held`). An attachment that could
not be read, more than fifty attachments, or more than 20 MB of them are
refused: forward such a message with `attachments` off.

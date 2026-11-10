/*
 * Evidence built at run time for the end-to-end tests and the documentation
 * screenshots: a harmless PE sample and a phishing e-mail. They are generated,
 * not stored, so no antivirus quarantines a fixture on a developer machine.
 */

/**
 * A harmless but valid PE32 (one .text section) with a few indicators inside.
 * .text starts with real x86 code at the entry point (test, branch, call a
 * helper, return) so the analyzer has functions and a CFG to show. The helper
 * loads the URL's address (mov eax, imm32), so the URL is linked to it.
 */
export function buildSamplePe() {
  const payload = Buffer.from(
    '\0\0kernel32.dll\0VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0http://185.220.101.47/gate.php\0' +
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinUpd\0',
    'latin1',
  )
  const entry = Buffer.from('5589e585c07405e8030000005dc390', 'hex')
  const helper = Buffer.from('b80000000031c0c3', 'hex')
  helper.writeUInt32LE(0x401000 + entry.length + helper.length + payload.indexOf('http'), 1)
  const code = Buffer.concat([entry, helper])
  const fileAlign = 0x200
  const rawSize = Math.ceil((code.length + payload.length) / fileAlign) * fileAlign
  const headers = Buffer.alloc(0x200)
  headers.write('MZ', 0, 'ascii')
  headers.writeUInt32LE(0x80, 0x3c)
  headers.write('PE\0\0', 0x80, 'ascii')
  // IMAGE_FILE_HEADER: i386, 1 section, timestamp, optional header size 0xe0, EXECUTABLE_IMAGE | 32BIT
  headers.writeUInt16LE(0x014c, 0x84)
  headers.writeUInt16LE(1, 0x86)
  headers.writeUInt32LE(0x5f5e1000, 0x88)
  headers.writeUInt16LE(0xe0, 0x94)
  headers.writeUInt16LE(0x0102, 0x96)
  // IMAGE_OPTIONAL_HEADER32
  const opt = 0x98
  headers.writeUInt16LE(0x10b, opt) // PE32 magic
  headers.writeUInt32LE(rawSize, opt + 4) // SizeOfCode
  headers.writeUInt32LE(0x1000, opt + 16) // AddressOfEntryPoint
  headers.writeUInt32LE(0x1000, opt + 20) // BaseOfCode
  headers.writeUInt32LE(0x400000, opt + 28) // ImageBase
  headers.writeUInt32LE(0x1000, opt + 32) // SectionAlignment
  headers.writeUInt32LE(fileAlign, opt + 36) // FileAlignment
  headers.writeUInt16LE(6, opt + 40) // MajorOperatingSystemVersion
  headers.writeUInt16LE(6, opt + 48) // MajorSubsystemVersion
  headers.writeUInt32LE(0x2000, opt + 56) // SizeOfImage
  headers.writeUInt32LE(0x200, opt + 60) // SizeOfHeaders
  headers.writeUInt16LE(2, opt + 68) // Subsystem: Windows GUI
  headers.writeUInt32LE(0x100000, opt + 72) // SizeOfStackReserve
  headers.writeUInt32LE(0x1000, opt + 76)
  headers.writeUInt32LE(0x100000, opt + 80)
  headers.writeUInt32LE(0x1000, opt + 84)
  headers.writeUInt32LE(16, opt + 92) // NumberOfRvaAndSizes
  // IMAGE_SECTION_HEADER for .text
  const sec = opt + 0xe0
  headers.write('.text', sec, 'ascii')
  headers.writeUInt32LE(code.length + payload.length, sec + 8) // VirtualSize
  headers.writeUInt32LE(0x1000, sec + 12) // VirtualAddress
  headers.writeUInt32LE(rawSize, sec + 16) // SizeOfRawData
  headers.writeUInt32LE(0x200, sec + 20) // PointerToRawData
  headers.writeUInt32LE(0x60000020, sec + 36) // CODE | EXECUTE | READ
  const body = Buffer.alloc(rawSize)
  code.copy(body)
  payload.copy(body, code.length)
  return Buffer.concat([headers, body])
}

/** A reported phishing e-mail: spoofed sender, deceptive link, an executable attachment. */
export function phishingEml() {
  const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(200)]).toString('base64')
  return [
    'Received: from mail.evil.example (mail.evil.example [185.220.101.47]) by mx.contoso.example; Tue, 10 Nov 2026 09:00:02 +0100',
    'From: "PayPal Service" <service@paypai.example>',
    'Reply-To: refunds@freemail.example',
    'To: m.rossi@contoso.example',
    'Subject: Your account will be suspended',
    'Date: Tue, 10 Nov 2026 08:59:50 +0100',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Verify your account immediately.</p><p style="font-size:0">filler</p>' +
      '<a href="https://login-paypa1.top/x">https://www.paypal.com/signin</a><script>alert(1)</script>',
    '--b1',
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
    'Content-Disposition: attachment; filename="invoice.pdf.exe"',
    'Content-Transfer-Encoding: base64',
    '',
    exe,
    '--b1--',
    '',
  ].join('\r\n')
}

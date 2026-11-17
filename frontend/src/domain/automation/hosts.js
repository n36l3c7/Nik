/*
 * A host as it is listed for a playbook. People paste addresses: what is
 * sent to the server is the host of the address (with its port, when one is
 * written), which is what the server compares connections with. The server
 * checks again and refuses what is not a host.
 */

/** `https://Hooks.Example.org:8443/path?x=1` → `hooks.example.org:8443`; other text is only trimmed and lower-cased. */
export function hostOf(text) {
  let value = String(text ?? '')
    .trim()
    .toLowerCase()
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
  // What follows the host in an address: a path, a query, a fragment.
  value = value.split(/[/?#]/)[0]
  return value.replace(/\.+$/, '')
}

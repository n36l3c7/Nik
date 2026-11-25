/*
 * Who owns the files dropped on the window. The app lets a file be dropped anywhere ("Nik finds the right
 * tab"); a page of host evidence (components/evidence/SourceFiles.jsx) takes the drop itself, so while one
 * is mounted the app's own overlay and handler stand down. A count, not a flag: two such pages may overlap
 * for a moment while the tabs change.
 */
let held = 0

/** Hold the drop for a page; the returned function gives it back (once). */
export function holdAppDrop() {
  held += 1
  let given = false
  return () => {
    if (given) return
    given = true
    held -= 1
  }
}

/** Whether a page has taken the drop away from the app. */
export const appDropHeld = () => held > 0

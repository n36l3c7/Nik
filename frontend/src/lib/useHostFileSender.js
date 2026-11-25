import { useCallback } from 'react'
import { useNavigation } from '../context/NavigationContext.jsx'
import { useToast } from '../context/ToastContext.jsx'
import { placeOf, placedText } from '../domain/collections.js'
import { uploadFile } from './chunkedUpload.js'
import { openCollection } from './collectionDialog.js'
import { transfer } from './transfers.js'
import { noteEvidenceChanged } from './useEvidenceSummary.js'

/**
 * `send(file, incidentId)`: a file of host evidence sent without saying what it is (`kind: "auto"`): the
 * server asks the worker, files it under its section, makes a collection of a zip, or refuses it with a sentence.
 * The answer is told to the person: a toast with a link to the page it went to, the sentence why not, or, for
 * a collection, its dialog. Resolves with the upload's answer, or null when it did not go.
 */
export function useHostFileSender() {
  const { showToast } = useToast()
  const { goTo } = useNavigation()
  return useCallback(
    async (file, incidentId) => {
      try {
        const result = await transfer(`Sending ${file.name}`, (onProgress) =>
          uploadFile(file, { incidentId, params: { kind: 'auto' }, onProgress }),
        )
        noteEvidenceChanged(incidentId)
        if (result.kind === 'collection' && result.sourceId) {
          openCollection(incidentId, result.sourceId)
          return result
        }
        const place = placeOf(result.kind)
        showToast({
          message: result.duplicate
            ? `${placedText(file.name, result.kind)} (already imported)`
            : placedText(file.name, result.kind),
          action: place ? { label: `Open ${place.label}`, run: () => goTo(place.tab) } : undefined,
        })
        return result
      } catch (failure) {
        // The sentence the server gives (a disk image, a .plaso file, no room) is shown as it comes.
        showToast({ message: `${file.name}: ${failure?.message || 'The file could not be sent.'}`, duration: 12000 })
        return null
      }
    },
    [showToast, goTo],
  )
}

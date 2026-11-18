import { useState } from 'react'
import { Pencil } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useFields } from '../../context/FieldsContext.jsx'
import { summarySections, typeOf, valuesOf } from '../../domain/fields.js'
import { Button } from '../ui/index.js'
import EditFieldsDialog from './EditFieldsDialog.jsx'
import FieldList from './FieldList.jsx'

/*
 * The sections of an incident's Summary, as the layout of its type arranges
 * them: each a card with its fields and an "Edit" that opens a form for them.
 * The side panel's section is not repeated here, and neither are the fields
 * the Summary's own form edits (name, ticket, host, user, system, severity,
 * status, owner).
 */

/**
 * @param {{ incident: object }} props
 */
export default function IncidentSections({ incident }) {
  const { can } = useAuth()
  const { types, fields, known, ready } = useFields()
  const [editing, setEditing] = useState(null) // the id of the section being edited
  if (!ready) return null
  const type = typeOf(types, incident)
  const sections = summarySections(type, fields)
  if (sections.length === 0) return null
  const values = valuesOf(incident)
  const open = sections.find((section) => section.id === editing) ?? null

  return (
    <div className="flex flex-col gap-4">
      {sections.map((section) => {
        const listed = section.fields.map((name) => known[name])
        return (
          <section key={section.id} aria-label={section.title} className="border border-line bg-panel">
            <div className="flex items-center gap-2 border-b border-line px-4 py-2">
              <h3 className="flex-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">{section.title}</h3>
              {can('write') && (
                <Button
                  variant="ghost"
                  size="xs"
                  icon={Pencil}
                  aria-label={`Edit ${section.title}`}
                  onClick={() => setEditing(section.id)}
                >
                  Edit
                </Button>
              )}
            </div>
            <div className="px-4 py-3">
              <FieldList fields={listed} values={values} columns={section.columns} />
            </div>
          </section>
        )
      })}
      {open && (
        <EditFieldsDialog
          incident={incident}
          type={type}
          title={open.title}
          fields={open.fields.map((name) => known[name])}
          values={values}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}

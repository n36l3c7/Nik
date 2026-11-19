import { useMemo } from 'react'
import { drawnWidgets } from '../../../domain/layoutGrid.js'
import Grid from '../../dashboards/Grid.jsx'
import LayoutWidget from './LayoutWidgets.jsx'

/*
 * A page of an incident as its type arranged it: the widgets of a grid, each
 * in its box, read and not moved. The Summary and the pages a type adds
 * (6.2) are drawn by this.
 */

const NOTHING = () => {}

/**
 * @param {{ incident: object, type: object | null, grid: object[], label: string }} props
 */
export default function PageGrid({ incident, type, grid, label }) {
  const widgets = useMemo(() => drawnWidgets(grid, type?.layout), [grid, type])
  return (
    <div aria-label={label} role="region">
      <Grid
        widgets={widgets}
        editing={false}
        onChange={NOTHING}
        onEdit={NOTHING}
        onDuplicate={NOTHING}
        onRemove={NOTHING}
        render={(widget) => <LayoutWidget widget={widget} incident={incident} type={type} />}
      />
    </div>
  )
}

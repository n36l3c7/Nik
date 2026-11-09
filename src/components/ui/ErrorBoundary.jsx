import { Component } from 'react'
import { RefreshCw } from 'lucide-react'
import AsciiSkull from './AsciiSkull.jsx'
import Button from './Button.jsx'
import EmptyState from './EmptyState.jsx'

/**
 * ErrorBoundary — contains a rendering error to the view that threw it.
 *
 * Without it, an exception while rendering one tab unmounts the whole app
 * and leaves an empty page. With it, the rest of Nik (sidebar, header, other
 * tabs) keeps working and the broken view offers to render itself again.
 * Give it a `resetKey` (e.g. tab + incident) so moving elsewhere clears the
 * error.
 *
 * @param {{ children: import('react').ReactNode, resetKey?: string, title?: string }} props
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
    this.retry = () => this.setState({ error: null })
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    // Keep the trace in the browser console for a bug report.
    console.error('View crashed:', error, info?.componentStack)
  }

  componentDidUpdate(previous) {
    if (this.state.error && previous.resetKey !== this.props.resetKey) this.retry()
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <EmptyState
        illustration={<AsciiSkull preset="medium" eyes="x" tone="muted" />}
        title={this.props.title ?? 'This view stopped working'}
        message={`${this.state.error.message || 'Unexpected error'}. The rest of Nik is unaffected; your data is safe on the server.`}
        action={
          <Button variant="secondary" size="sm" icon={RefreshCw} onClick={this.retry}>
            Reload this view
          </Button>
        }
      />
    )
  }
}

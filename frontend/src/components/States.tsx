import { Component, type ReactNode } from 'react'

export function LoadingState({ label = 'Loading assessment data…' }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <div className="skeleton" />
      <div className="skeleton" style={{ width: '70%' }} />
      <p>{label}</p>
    </div>
  )
}

export function EmptyState({
  title,
  body,
  action,
}: {
  title: string
  body: string
  action?: ReactNode
}) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      <p>{body}</p>
      {action}
    </div>
  )
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="error-banner" role="alert">
      {message}
    </div>
  )
}

export class ErrorBoundary extends Component<{ children: ReactNode }, { message: string | null }> {
  state = { message: null as string | null }

  static getDerivedStateFromError(error: unknown) {
    return {
      message: error instanceof Error ? error.message : 'The interface encountered an unexpected error.',
    }
  }

  render() {
    if (this.state.message) {
      return <ErrorBanner message={this.state.message} />
    }
    return this.props.children
  }
}

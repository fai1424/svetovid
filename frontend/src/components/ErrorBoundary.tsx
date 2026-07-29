// Q10: top-level + per-pane error boundary.
//
// A single malformed event, a ReactMarkdown crash on bad input, or a thrown
// error inside any pane could otherwise blank the whole app. This boundary
// catches those, logs them, and renders a compact fallback with a "Try again"
// affordance (resets internal state so the wrapped subtree re-mounts fresh).
//
// Used at two scopes:
//   - App.tsx wraps the whole <main> so a screen crash degrades gracefully.
//   - Investigation.tsx wraps each of the three panes so one pane failing
//     doesn't take out the other two.

import { Component, ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: any) {
    // eslint-disable-next-line no-console
    console.error("ErrorBoundary caught:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <div className="p-lg text-center">
            <h2 className="text-sm font-semibold text-destructive mb-sm">
              Something went wrong
            </h2>
            <p className="text-xs text-muted-fg mb-md">
              {this.state.error?.message}
            </p>
            <button
              className="text-xs text-accent hover:underline"
              onClick={() => this.setState({ hasError: false })}
            >
              Try again
            </button>
          </div>
        )
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;

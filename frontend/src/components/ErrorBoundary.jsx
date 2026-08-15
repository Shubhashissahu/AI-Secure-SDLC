import { Component } from "react";

/**
 * FIX #26: Global React Error Boundary.
 * Previously the app had no error boundary — any uncaught render error
 * would crash the entire UI to a blank white screen with no recovery option.
 * This wraps the app and shows a user-friendly error + reload button instead.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error("[ErrorBoundary] Uncaught error:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4">
          <div className="text-center max-w-md">
            <div className="text-5xl mb-4">⚠️</div>
            <h1 className="text-xl font-bold text-white mb-2">Something went wrong</h1>
            <p className="text-slate-400 text-sm mb-6">
              An unexpected error occurred. Please reload the page or contact support if the issue persists.
            </p>
            {this.state.error && (
              <pre className="text-xs text-red-400 bg-slate-900 border border-slate-800 rounded-lg p-4 text-left mb-6 overflow-auto max-h-32">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={() => window.location.reload()}
              className="bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2 px-6 rounded-lg text-sm transition-colors"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

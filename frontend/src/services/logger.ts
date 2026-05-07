import { api } from './api';

export const logEvent = async (action: string, message: string, metadata: any = {}) => {
  try {
    await api.post('/dam/record', {
      event_type: 'ui_interaction',
      severity: 'low',
      action,
      message,
      metadata: {
        ...metadata,
        url: window.location.href,
        userAgent: navigator.userAgent,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (err) {
    // Fail silently to not disrupt UI
    console.debug('Failed to record audit event', err);
  }
};

export const initGlobalLogger = () => {
  if (typeof window === 'undefined') return;

  // 1. Log clicks
  window.addEventListener('click', (e: MouseEvent) => {
    const target = e.target as HTMLElement;
    const text = target.innerText?.slice(0, 50) || target.id || target.tagName;
    logEvent('click', `User clicked on ${target.tagName}: ${text}`, {
      tagName: target.tagName,
      id: target.id,
      className: target.className,
    });
  }, true);

  // 2. Log navigation (popstate)
  window.addEventListener('popstate', () => {
    logEvent('navigation', `User navigated to ${window.location.pathname}`);
  });

  // 3. Log errors
  window.addEventListener('error', (e: ErrorEvent) => {
    logEvent('js_error', `JavaScript error: ${e.message}`, {
      filename: e.filename,
      lineno: e.lineno,
      colno: e.colno,
      stack: e.error?.stack,
    });
  });
};

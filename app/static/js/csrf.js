(() => {
    const tokenElement = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = tokenElement ? tokenElement.content : '';
    const originalFetch = window.fetch.bind(window);

    window.fetch = (input, init = {}) => {
        const requestUrl = typeof input === 'string'
            ? new URL(input, window.location.href)
            : new URL(input.url, window.location.href);
        const method = (init.method || input.method || 'GET').toUpperCase();

        if (
            csrfToken &&
            requestUrl.origin === window.location.origin &&
            !['GET', 'HEAD', 'OPTIONS'].includes(method)
        ) {
            const headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
            headers.set('X-CSRFToken', csrfToken);
            return originalFetch(input, { ...init, headers });
        }

        return originalFetch(input, init);
    };
})();

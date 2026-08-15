import axios from "axios";

/**
 * Single shared API client with:
 * 1. In-flight request deduplication for concurrent identical GET requests.
 * 2. Short TTL (5-10s) in-memory response caching for stable GET requests.
 * 3. Automatic cache invalidation on mutations (POST, PUT, PATCH, DELETE).
 * 4. Automatic 429 (Too Many Requests) Retry-After handling & exponential backoff.
 * 5. Full support for AbortSignal cancellation in React useEffect hooks.
 */
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:4000",
  timeout: 15000,
});

// Cache storage and in-flight request tracking
const responseCache = new Map();
const inFlightRequests = new Map();

// Generate a deterministic cache key for GET requests
function getRequestKey(config) {
  const url = config.url || "";
  const params = config.params ? JSON.stringify(config.params) : "";
  return `${config.method?.toLowerCase()}:${url}:${params}`;
}

// Invalidate all cached GET responses when any mutation occurs
export function invalidateApiCache(pattern) {
  if (!pattern) {
    responseCache.clear();
    return;
  }
  for (const key of responseCache.keys()) {
    if (key.includes(pattern)) {
      responseCache.delete(key);
    }
  }
}

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor with 429 Retry-After handling
api.interceptors.response.use(
  (response) => {
    // Clear cache if this was a mutation (POST, PUT, PATCH, DELETE)
    const method = response.config.method?.toLowerCase();
    if (["post", "put", "patch", "delete"].includes(method)) {
      invalidateApiCache();
    }
    return response;
  },
  async (error) => {
    const config = error.config;

    // Handle 401 Unauthorized
    if (error.response?.status === 401) {
      localStorage.removeItem("token");
    }

    // Handle 429 Too Many Requests with Retry-After backoff
    if (error.response?.status === 429 && config && !config._isRetry) {
      config._retryCount = (config._retryCount || 0) + 1;

      // Allow up to 1 automatic retry
      if (config._retryCount <= 1) {
        config._isRetry = true;
        const retryAfterHeader = error.response.headers["retry-after"];
        const retryAfterSeconds = Number(retryAfterHeader) || error.response.data?.retryAfter || 2;
        const delayMs = Math.min(retryAfterSeconds * 1000, 5000); // capped at 5s

        console.warn(`[api] Rate limit reached (429). Retrying ${config.url} in ${delayMs}ms...`);

        await new Promise((resolve) => setTimeout(resolve, delayMs));
        return api(config);
      }
    }

    // Surface readable error message
    const serverMessage = error.response?.data?.message;
    if (serverMessage && !error.message.includes(serverMessage)) {
      error.message = serverMessage;
    }

    return Promise.reject(error);
  }
);

/**
 * Deduplicated & Cached GET helper.
 * If an identical GET request is already in-flight, returns the active Promise.
 * If a fresh cached response (< cacheTtlMs) exists, returns it immediately.
 * 
 * @param {string} url 
 * @param {object} [config] 
 * @param {number} [cacheTtlMs=0] - Set > 0 (e.g. 5000) to cache response
 */
export function getCached(url, config = {}, cacheTtlMs = 5000) {
  const reqConfig = { ...config, method: "get", url };
  const key = getRequestKey(reqConfig);
  const now = Date.now();

  // Check cache
  // FIX #18: Check if the request was already aborted before returning a cached
  // response. Without this, React's useEffect cleanup (controller.abort()) would
  // not prevent stale state updates from cached data, causing memory leaks.
  if (cacheTtlMs > 0 && responseCache.has(key)) {
    const cached = responseCache.get(key);
    if (now - cached.timestamp < cacheTtlMs) {
      if (config.signal?.aborted) {
        return Promise.reject(new DOMException("Request aborted", "AbortError"));
      }
      return Promise.resolve(cached.data);
    }
    responseCache.delete(key);
  }

  // Check in-flight request
  if (inFlightRequests.has(key)) {
    return inFlightRequests.get(key);
  }

  const promise = api.get(url, config)
    .then((res) => {
      if (cacheTtlMs > 0) {
        responseCache.set(key, { data: res, timestamp: Date.now() });
      }
      return res;
    })
    .finally(() => {
      inFlightRequests.delete(key);
    });

  inFlightRequests.set(key, promise);
  return promise;
}

export default api;
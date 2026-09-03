package org.ipsecuz.opprotection.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Thread-safe sliding lockout used for password and 2FA attempts. */
public final class AttemptLimiter {
    private final Map<String, State> states = new ConcurrentHashMap<>();
    private volatile int maxAttempts;
    private volatile long windowMillis;
    private volatile long lockoutMillis;

    public AttemptLimiter(int maxAttempts, long windowSeconds, long lockoutSeconds) {
        reload(maxAttempts, windowSeconds, lockoutSeconds);
    }

    public void reload(int maxAttempts, long windowSeconds, long lockoutSeconds) {
        this.maxAttempts = Math.max(1, maxAttempts);
        this.windowMillis = Math.max(1L, windowSeconds) * 1000L;
        this.lockoutMillis = Math.max(1L, lockoutSeconds) * 1000L;
    }

    public Result check(String key) {
        if (key == null) return Result.allow();
        long now = System.currentTimeMillis();
        State state = states.get(key);
        if (state == null) return Result.allow();
        synchronized (state) {
            if (state.lockedUntil > now) return Result.locked(state.lockedUntil - now);
            if (now - state.windowStarted > windowMillis) {
                states.remove(key, state);
                return Result.allow();
            }
            return Result.allow();
        }
    }

    public Result failure(String key) {
        if (key == null) return Result.allow();
        long now = System.currentTimeMillis();
        State state = states.computeIfAbsent(key, ignored -> new State(now));
        synchronized (state) {
            if (state.lockedUntil > now) return Result.locked(state.lockedUntil - now);
            if (now - state.windowStarted > windowMillis) {
                state.windowStarted = now;
                state.failures = 0;
            }
            state.failures++;
            if (state.failures >= maxAttempts) {
                state.lockedUntil = now + lockoutMillis;
                state.failures = 0;
                return Result.locked(lockoutMillis);
            }
            return Result.remaining(maxAttempts - state.failures);
        }
    }

    public void success(String key) {
        if (key != null) states.remove(key);
    }

    public void clear() {
        states.clear();
    }

    private static final class State {
        private long windowStarted;
        private long lockedUntil;
        private int failures;
        private State(long now) { this.windowStarted = now; }
    }

    public record Result(boolean allowed, boolean locked, int remainingAttempts, long remainingMillis) {
        static Result allow() { return new Result(true, false, Integer.MAX_VALUE, 0L); }
        static Result remaining(int remaining) { return new Result(true, false, Math.max(0, remaining), 0L); }
        static Result locked(long remaining) { return new Result(false, true, 0, Math.max(0L, remaining)); }
    }
}

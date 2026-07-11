package org.ipsecuz.opprotection.security;

import org.bukkit.Bukkit;
import org.ipsecuz.opprotection.OPProtection;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Standalone premium-profile resolver adapted from JPremium's resolver strategy.
 *
 * <p>The resolver supports three safe runtime paths:</p>
 * <ul>
 *     <li>Online-mode: the authenticated login UUID must equal the official Premium UUID.</li>
 *     <li>Proxy forwarding: the securely forwarded UUID must equal the official Premium UUID.</li>
 *     <li>Standalone offline-mode: only Premium profile existence can be checked. Because an
 *     offline-mode server does not perform Mojang's encrypted session authentication, ownership
 *     cannot be proven from a Bukkit pre-login event. In this path OPProtection therefore keeps
 *     password/console/Discord verification mandatory and never grants the Premium 2FA bypass.</li>
 * </ul>
 *
 * <p>A Mojang profile lookup alone is never treated as proof that the connecting client owns
 * the account.</p>
 */
public final class PremiumAccountChecker {
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_]{2,16}");
    private static final Pattern ID = Pattern.compile("\\\"id\\\"\\s*:\\s*\\\"([0-9a-fA-F-]{32,36})\\\"");
    private static final Pattern NAME = Pattern.compile("\\\"name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final String[] ENDPOINTS = {
            "https://api.mojang.com/users/profiles/minecraft/",
            "https://api.minecraftservices.com/minecraft/profile/lookup/name/"
    };
    private static final int MAX_CACHE_ENTRIES = 2048;
    private static final long ERROR_CACHE_MILLIS = 30_000L;
    private static final long RETRY_BASE_DELAY_MILLIS = 250L;

    private final OPProtection plugin;
    private final ConcurrentMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, CompletableFuture<LookupResult>> inFlight = new ConcurrentHashMap<>();

    private volatile HttpClient client;
    private volatile long timeoutMillis;
    private volatile long cacheMillis;
    private volatile int lookupRetries;
    private volatile boolean failClosed;
    private volatile boolean requireExactNameCase;

    public PremiumAccountChecker(OPProtection plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        this.timeoutMillis = Math.max(500L, Math.min(10_000L,
                plugin.getConfig().getLong("premium-auth.mojang-timeout-ms", 3000L)));
        this.cacheMillis = Math.max(1L,
                plugin.getConfig().getLong("premium-auth.cache-seconds", 3600L)) * 1000L;
        this.lookupRetries = Math.max(1, Math.min(3,
                plugin.getConfig().getInt("premium-auth.lookup-retries", 2)));
        this.failClosed = plugin.getConfig().getBoolean("premium-auth.fail-closed", true);
        this.requireExactNameCase = plugin.getConfig().getBoolean(
                "premium-auth.require-exact-name-case", false);
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMillis))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        cache.clear();
        inFlight.clear();
    }

    public LookupResult lookup(String playerName) {
        if (playerName == null || !USERNAME.matcher(playerName).matches()) {
            return LookupResult.invalid("Tên người chơi không hợp lệ");
        }

        String key = playerName.toLowerCase(Locale.ROOT);
        long now = System.currentTimeMillis();
        CacheEntry cached = cache.get(key);
        if (cached != null && cached.expiresAt > now) return cached.result;
        if (cached != null) cache.remove(key, cached);

        CompletableFuture<LookupResult> created = new CompletableFuture<>();
        CompletableFuture<LookupResult> existing = inFlight.putIfAbsent(key, created);
        if (existing != null) {
            try {
                return existing.join();
            } catch (RuntimeException ex) {
                return LookupResult.error("Dịch vụ xác minh Premium đang không khả dụng");
            }
        }

        try {
            LookupResult result = query(playerName);
            long ttl = result.status == LookupStatus.ERROR
                    ? Math.min(ERROR_CACHE_MILLIS, cacheMillis)
                    : cacheMillis;
            cache.put(key, new CacheEntry(result, now + Math.max(1_000L, ttl)));
            evictExpiredEntries(now);
            created.complete(result);
            return result;
        } catch (RuntimeException ex) {
            LookupResult result = LookupResult.error("Dịch vụ xác minh Premium đang không khả dụng");
            created.complete(result);
            return result;
        } finally {
            inFlight.remove(key, created);
        }
    }

    public PremiumResult check(String playerName, UUID joinedUuid) {
        LookupResult lookup = lookup(playerName);
        if (lookup.status == LookupStatus.NOT_FOUND || lookup.status == LookupStatus.INVALID) {
            return PremiumResult.invalid(lookup.reason);
        }
        if (lookup.status == LookupStatus.ERROR) {
            if (failClosed) return PremiumResult.invalid(lookup.reason);
            return PremiumResult.lookupBypass(lookup.reason);
        }
        if (requireExactNameCase && !lookup.officialName.equals(playerName)) {
            return PremiumResult.invalid("Tên đăng nhập không khớp chính xác chữ hoa/thường của hồ sơ Mojang");
        }
        if (joinedUuid == null) {
            return PremiumResult.invalid("Không nhận được UUID đăng nhập");
        }

        // Online-mode and correctly configured proxy forwarding both deliver the official UUID.
        if (lookup.officialUuid.equals(joinedUuid)) {
            return PremiumResult.verified(lookup.officialName, lookup.officialUuid, joinedUuid);
        }

        RuntimeMode mode = runtimeMode();
        UUID expectedOfflineUuid = offlineUuid(playerName);
        if (mode == RuntimeMode.STANDALONE_OFFLINE && expectedOfflineUuid.equals(joinedUuid)) {
            return PremiumResult.profileOnly(
                    lookup.officialName,
                    lookup.officialUuid,
                    joinedUuid,
                    "Đã tìm thấy hồ sơ Premium, nhưng server standalone offline-mode không thể chứng minh quyền sở hữu; "
                            + "password và lớp xác minh phụ vẫn bắt buộc."
            );
        }

        if (mode == RuntimeMode.PROXY_FORWARDED) {
            return PremiumResult.invalid(
                    "UUID proxy chuyển xuống không khớp UUID Premium chính thức. "
                            + "Hãy kiểm tra modern/legacy forwarding và firewall backend."
            );
        }
        if (mode == RuntimeMode.ONLINE_MODE) {
            return PremiumResult.invalid("UUID online-mode không khớp UUID Premium chính thức");
        }
        return PremiumResult.invalid(
                "UUID đăng nhập không phải UUID offline dự kiến hoặc UUID Premium chính thức; có dấu hiệu spoof forwarding."
        );
    }

    public RuntimeMode runtimeMode() {
        if (Bukkit.getOnlineMode()) return RuntimeMode.ONLINE_MODE;
        if (plugin.getConfig().getBoolean("ip-forwarding", false)) return RuntimeMode.PROXY_FORWARDED;
        return RuntimeMode.STANDALONE_OFFLINE;
    }

    public static UUID offlineUuid(String playerName) {
        String normalized = playerName == null ? "" : playerName;
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + normalized).getBytes(StandardCharsets.UTF_8));
    }

    private LookupResult query(String playerName) {
        String encoded = URLEncoder.encode(playerName, StandardCharsets.UTF_8);
        IOException lastFailure = null;
        boolean definitiveNotFound = false;

        for (int attempt = 0; attempt < lookupRetries; attempt++) {
            if (attempt > 0 && !sleepBackoff(attempt)) {
                return LookupResult.error("Tra cứu Premium bị gián đoạn");
            }

            int notFoundEndpoints = 0;
            boolean transientFailure = false;
            for (String endpoint : ENDPOINTS) {
                try {
                    HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint + encoded))
                            .timeout(Duration.ofMillis(timeoutMillis))
                            .header("Accept", "application/json")
                            .header("User-Agent", "OPProtection/" + plugin.getDescription().getVersion())
                            .GET()
                            .build();
                    HttpResponse<String> response = client.send(
                            request,
                            HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

                    int status = response.statusCode();
                    if (status == 204 || status == 404) {
                        definitiveNotFound = true;
                        notFoundEndpoints++;
                        continue;
                    }
                    if (status == 429 || status >= 500) {
                        transientFailure = true;
                        lastFailure = new IOException("HTTP " + status + " từ " + endpoint);
                        continue;
                    }
                    if (status < 200 || status >= 300) {
                        lastFailure = new IOException("HTTP " + status + " từ " + endpoint);
                        continue;
                    }

                    LookupResult parsed = parseProfile(response.body(), playerName);
                    if (parsed.status == LookupStatus.FOUND) return parsed;
                    lastFailure = new IOException(parsed.reason);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    return LookupResult.error("Tra cứu Premium bị gián đoạn");
                } catch (IOException | IllegalArgumentException ex) {
                    transientFailure = true;
                    lastFailure = ex instanceof IOException io ? io : new IOException(ex);
                }
            }

            if (notFoundEndpoints == ENDPOINTS.length && !transientFailure) {
                return LookupResult.notFound("Không tìm thấy tài khoản Minecraft Java Premium");
            }
        }

        if (definitiveNotFound && lastFailure == null) {
            return LookupResult.notFound("Không tìm thấy tài khoản Minecraft Java Premium");
        }

        String detail = lastFailure == null
                ? "Không tìm thấy tài khoản Minecraft Java Premium"
                : lastFailure.getMessage();
        plugin.getLogger().warning("[PreAuth] Không thể tra cứu " + playerName + ": " + detail);
        return definitiveNotFound
                ? LookupResult.notFound("Không tìm thấy tài khoản Minecraft Java Premium")
                : LookupResult.error("Dịch vụ xác minh Premium đang không khả dụng");
    }

    private static LookupResult parseProfile(String body, String fallbackName) {
        String json = body == null ? "" : body;
        Matcher idMatcher = ID.matcher(json);
        Matcher nameMatcher = NAME.matcher(json);
        if (!idMatcher.find()) return LookupResult.error("Phản hồi profile không có UUID hợp lệ");

        UUID uuid = parseUuid(idMatcher.group(1));
        String officialName = nameMatcher.find() ? nameMatcher.group(1) : fallbackName;
        return LookupResult.found(officialName, uuid);
    }

    private static boolean sleepBackoff(int attempt) {
        long delay = Math.min(2_000L, RETRY_BASE_DELAY_MILLIS * (1L << (attempt - 1)));
        try {
            Thread.sleep(delay);
            return true;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private void evictExpiredEntries(long now) {
        if (cache.size() <= MAX_CACHE_ENTRIES) return;
        cache.entrySet().removeIf(entry -> entry.getValue().expiresAt <= now);
        if (cache.size() <= MAX_CACHE_ENTRIES) return;

        int removeCount = cache.size() - MAX_CACHE_ENTRIES;
        for (String key : cache.keySet()) {
            if (removeCount-- <= 0) break;
            cache.remove(key);
        }
    }

    private static UUID parseUuid(String input) {
        String raw = input == null ? "" : input.replace("-", "");
        if (raw.length() != 32 || !raw.matches("[0-9a-fA-F]{32}")) {
            throw new IllegalArgumentException("UUID profile không hợp lệ");
        }
        return UUID.fromString(raw.substring(0, 8) + '-' + raw.substring(8, 12) + '-'
                + raw.substring(12, 16) + '-' + raw.substring(16, 20) + '-' + raw.substring(20));
    }

    public enum RuntimeMode {
        ONLINE_MODE,
        PROXY_FORWARDED,
        STANDALONE_OFFLINE
    }

    public enum VerificationLevel {
        VERIFIED_PREMIUM,
        STANDALONE_PROFILE_ONLY,
        LOOKUP_BYPASS
    }

    public enum LookupStatus { FOUND, NOT_FOUND, ERROR, INVALID }

    public static final class LookupResult {
        private final LookupStatus status;
        private final String officialName;
        private final UUID officialUuid;
        private final String reason;

        private LookupResult(LookupStatus status, String officialName, UUID officialUuid, String reason) {
            this.status = status;
            this.officialName = officialName;
            this.officialUuid = officialUuid;
            this.reason = reason;
        }

        public static LookupResult found(String name, UUID uuid) {
            return new LookupResult(LookupStatus.FOUND, name, uuid, "OK");
        }

        public static LookupResult notFound(String reason) {
            return new LookupResult(LookupStatus.NOT_FOUND, null, null, reason);
        }

        public static LookupResult error(String reason) {
            return new LookupResult(LookupStatus.ERROR, null, null, reason);
        }

        public static LookupResult invalid(String reason) {
            return new LookupResult(LookupStatus.INVALID, null, null, reason);
        }

        public LookupStatus status() { return status; }
        public String officialName() { return officialName; }
        public UUID officialUuid() { return officialUuid; }
        public String reason() { return reason; }
        public boolean found() { return status == LookupStatus.FOUND; }
    }

    private record CacheEntry(LookupResult result, long expiresAt) { }

    public static final class PremiumResult {
        private final boolean valid;
        private final VerificationLevel level;
        private final String reason;
        private final String officialName;
        private final UUID officialUuid;
        private final UUID joinedUuid;

        private PremiumResult(
                boolean valid,
                VerificationLevel level,
                String reason,
                String officialName,
                UUID officialUuid,
                UUID joinedUuid
        ) {
            this.valid = valid;
            this.level = level;
            this.reason = reason;
            this.officialName = officialName;
            this.officialUuid = officialUuid;
            this.joinedUuid = joinedUuid;
        }

        public static PremiumResult verified(String name, UUID officialUuid, UUID joinedUuid) {
            return new PremiumResult(true, VerificationLevel.VERIFIED_PREMIUM,
                    "OK", name, officialUuid, joinedUuid);
        }

        public static PremiumResult profileOnly(
                String name,
                UUID officialUuid,
                UUID joinedUuid,
                String reason
        ) {
            return new PremiumResult(true, VerificationLevel.STANDALONE_PROFILE_ONLY,
                    reason, name, officialUuid, joinedUuid);
        }

        public static PremiumResult lookupBypass(String reason) {
            return new PremiumResult(true, VerificationLevel.LOOKUP_BYPASS,
                    reason, null, null, null);
        }

        public static PremiumResult invalid(String reason) {
            return new PremiumResult(false, null, reason, null, null, null);
        }

        public boolean isValid() { return valid; }
        public boolean isStronglyVerified() { return level == VerificationLevel.VERIFIED_PREMIUM; }
        public boolean isLookupBypassed() { return level == VerificationLevel.LOOKUP_BYPASS; }
        public boolean isProfileOnly() { return level == VerificationLevel.STANDALONE_PROFILE_ONLY; }
        public VerificationLevel getLevel() { return level; }
        public String getReason() { return reason; }
        public String getOfficialName() { return officialName; }
        public UUID getOfficialUuid() { return officialUuid; }
        public UUID getJoinedUuid() { return joinedUuid; }
    }
}

package org.ipsecuz.opprotection.utils;

import org.ipsecuz.opprotection.OPProtection;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** HTTPS GeoIP client with bounded timeouts, outage throttling and cache. */
public final class GeoIPChecker {
    private static final Pattern COUNTRY = Pattern.compile("\\\"country_code\\\"\\s*:\\s*\\\"([A-Za-z]{2})\\\"");
    private static final Pattern SUCCESS = Pattern.compile("\\\"success\\\"\\s*:\\s*(true|false)");
    private final OPProtection plugin;
    private final ConcurrentMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final AtomicLong lastUnavailableWarning = new AtomicLong();
    private volatile HttpClient client;
    private volatile boolean enabled;
    private volatile Set<String> allowedCountries = Set.of();
    private volatile long timeoutMillis;
    private volatile long cacheMillis;
    private volatile boolean failClosed;

    public GeoIPChecker(OPProtection plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        this.enabled = plugin.getConfig().getBoolean("geoip.enabled", false);
        Set<String> countries = new HashSet<>();
        for (String item : plugin.getConfig().getStringList("geoip.allowed-countries")) {
            if (item != null && !item.isBlank()) countries.add(item.trim().toUpperCase(Locale.ROOT));
        }
        this.allowedCountries = Set.copyOf(countries);
        this.timeoutMillis = Math.max(500L, Math.min(10_000L,
                plugin.getConfig().getLong("geoip.timeout-ms", 3000L)));
        this.cacheMillis = Math.max(30L,
                plugin.getConfig().getLong("geoip.cache-seconds", 1800L)) * 1000L;
        this.failClosed = plugin.getConfig().getBoolean("geoip.fail-closed", true);
        rebuildClient(timeoutMillis);
        cache.clear();
    }

    public Result check(String ip) {
        if (!enabled) return Result.allowed("DISABLED");
        if (isPrivateOrLocal(ip)) return Result.allowed("PRIVATE");

        long now = System.currentTimeMillis();
        CacheEntry cached = cache.get(ip);
        if (cached != null && cached.expiresAt > now) return cached.result;

        Result result = query(ip);
        long configured = cacheMillis;
        long ttl = result.countryCode.equals("UNAVAILABLE") ? Math.min(configured, 60_000L) : configured;
        cache.put(ip, new CacheEntry(result, now + ttl));
        if (cache.size() > 4096) cache.entrySet().removeIf(entry -> entry.getValue().expiresAt <= now);
        return result;
    }

    public boolean isCountryAllowed(String ip) {
        return check(ip).allowed;
    }

    private Result query(String ip) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://ipwho.is/" + ip + "?fields=success,country_code"))
                    .timeout(Duration.ofMillis(timeoutMillis))
                    .header("Accept", "application/json")
                    .header("User-Agent", "OPProtection/" + plugin.getDescription().getVersion())
                    .GET().build();
            HttpResponse<String> response = client().send(request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return unavailable("HTTP " + response.statusCode());
            }
            String body = response.body() == null ? "" : response.body();
            Matcher success = SUCCESS.matcher(body);
            if (success.find() && !Boolean.parseBoolean(success.group(1))) return unavailable("GeoIP success=false");
            Matcher country = COUNTRY.matcher(body);
            if (!country.find()) return unavailable("Không có country_code");
            String code = country.group(1).toUpperCase(Locale.ROOT);
            return allowedCountries.contains(code) ? Result.allowed(code) : Result.blocked(code);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return unavailable("interrupted");
        } catch (Exception ex) {
            return unavailable(ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
    }

    private Result unavailable(String reason) {
        boolean closeOnFailure = failClosed;
        long now = System.currentTimeMillis();
        long previous = lastUnavailableWarning.get();
        if (now - previous >= 60_000L && lastUnavailableWarning.compareAndSet(previous, now)) {
            plugin.getLogger().warning("[GeoIP] Dịch vụ không khả dụng: " + reason + " | fail-closed=" + closeOnFailure);
        }
        return closeOnFailure ? Result.blocked("UNAVAILABLE") : Result.allowed("UNAVAILABLE");
    }

    private HttpClient client() { return client; }

    private void rebuildClient(long timeoutMillis) {
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMillis))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private boolean isPrivateOrLocal(String rawIp) {
        try {
            InetAddress address = InetAddress.getByName(rawIp);
            return address.isAnyLocalAddress() || address.isLoopbackAddress()
                    || address.isLinkLocalAddress() || address.isSiteLocalAddress();
        } catch (Exception ignored) {
            return false;
        }
    }

    public record Result(boolean allowed, String countryCode) {
        public static Result allowed(String code) { return new Result(true, code); }
        public static Result blocked(String code) { return new Result(false, code); }
    }

    private record CacheEntry(Result result, long expiresAt) { }
}

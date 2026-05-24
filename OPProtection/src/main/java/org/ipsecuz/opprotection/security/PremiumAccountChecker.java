package org.ipsecuz.opprotection.security;

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
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PremiumAccountChecker {
    private static final Pattern A = Pattern.compile("\\\"id\\\"\\s*:\\s*\\\"([0-9a-fA-F]{32})\\\"");
    private static final Pattern B = Pattern.compile("\\\"name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    private final OPProtection a;
    private final HttpClient b;
    private final ConcurrentMap<String, C> c = new ConcurrentHashMap<>();

    public PremiumAccountChecker(OPProtection plugin) {
        this.a = plugin;
        this.b = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(this.a.getConfig().getLong(k(0), 3000L)))
                .build();
    }

    public PremiumResult check(String playerName, UUID joinedUuid) {
        if (playerName == null || playerName.isBlank() || joinedUuid == null) {
            return PremiumResult.invalid(k(1));
        }

        String x = playerName.toLowerCase(Locale.ROOT);
        long n = System.currentTimeMillis();
        long ttl = Math.max(0L, this.a.getConfig().getLong(k(2), 3600L)) * 1000L;
        C hit = this.c.get(x);
        if (hit != null && n - hit.c() <= ttl) {
            return b(playerName, joinedUuid, hit.a(), hit.b());
        }

        Optional<D> p = a(playerName);
        if (p.isEmpty()) {
            return b(playerName, joinedUuid, null, null);
        }

        UUID u = p.map(D::a).orElse(null);
        String o = p.map(D::b).orElse(null);
        if (u != null || !this.a.getConfig().getBoolean(k(6), true)) {
            this.c.put(x, new C(u, o, n));
        }
        return b(playerName, joinedUuid, u, o);
    }

    private Optional<D> a(String n) {
        try {
            String e = URLEncoder.encode(n, StandardCharsets.UTF_8);
            HttpRequest r = HttpRequest.newBuilder()
                    .uri(URI.create(k(3) + e))
                    .timeout(Duration.ofMillis(this.a.getConfig().getLong(k(0), 3000L)))
                    .GET()
                    .build();
            HttpResponse<String> h = this.b.send(r, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            int code = h.statusCode();
            if (code == 204 || code == 404) {
                return Optional.empty();
            }
            if (code < 200 || code >= 300) {
                throw new IOException(k(4) + code);
            }
            String body = h.body();
            Matcher i = A.matcher(body == null ? "" : body);
            Matcher m = B.matcher(body == null ? "" : body);
            if (!i.find()) {
                throw new IOException(k(5));
            }
            String id = i.group(1);
            if (id == null || id.length() != 32) {
                throw new IOException(k(5));
            }
            String on = m.find() ? m.group(1) : n;
            return Optional.of(new D(c(id), on));
        } catch (Exception ex) {
            if (this.a.getConfig().getBoolean(k(6), true)) {
                this.a.getLogger().warning(k(7) + n + k(8) + ex.getMessage());
                return Optional.empty();
            }
            this.a.getLogger().warning(k(9) + n + k(10) + ex.getMessage());
            return Optional.of(new D(null, n));
        }
    }

    private PremiumResult b(String n, UUID j, UUID u, String on) {
        if (u == null) {
            if (!this.a.getConfig().getBoolean(k(6), true)) {
                return PremiumResult.validBypass(k(11));
            }
            return PremiumResult.invalid(k(12));
        }
        if (!u.equals(j)) {
            return PremiumResult.invalid(k(13) + u + k(14) + j);
        }
        if (this.a.getConfig().getBoolean(k(15), false) && on != null && !on.equals(n)) {
            return PremiumResult.invalid(k(16) + on + k(14) + n);
        }
        return PremiumResult.valid(on == null ? n : on, u);
    }

    private static UUID c(String r) {
        if (r == null) {
            throw new IllegalArgumentException("missing uuid");
        }
        String v = r.replace("-", "");
        if (v.length() != 32) {
            throw new IllegalArgumentException("bad uuid length");
        }
        return UUID.fromString(v.substring(0, 8) + "-" + v.substring(8, 12) + "-" + v.substring(12, 16) + "-" + v.substring(16, 20) + "-" + v.substring(20));
    }

    private static String k(int i) {
        return switch (i) {
            case 0 -> "premium-auth.mojang-timeout-ms";
            case 1 -> "Invalid player profile";
            case 2 -> "premium-auth.cache-seconds";
            case 3 -> "https://api.mojang.com/users/profiles/minecraft/";
            case 4 -> "Mojang API returned HTTP ";
            case 5 -> "Mojang API response has no UUID";
            case 6 -> "premium-auth.fail-closed";
            case 7 -> "[PremiumAuth] Could not verify ";
            case 8 -> ": ";
            case 9 -> "[PremiumAuth] Mojang lookup failed for ";
            case 10 -> " but fail-closed=false: ";
            case 11 -> "Lookup unavailable and fail-closed=false";
            case 12 -> "This nickname is not a verified premium account or Mojang lookup failed";
            case 13 -> "UUID mismatch: official=";
            case 14 -> ", joined=";
            case 15 -> "premium-auth.require-exact-name-case";
            case 16 -> "Name case mismatch: official=";
            default -> "";
        };
    }

    private record D(UUID a, String b) {}
    private record C(UUID a, String b, long c) {}

    public static final class PremiumResult {
        private final boolean valid;
        private final boolean lookupBypassed;
        private final String reason;
        private final String officialName;
        private final UUID officialUuid;

        private PremiumResult(boolean valid, boolean lookupBypassed, String reason, String officialName, UUID officialUuid) {
            this.valid = valid;
            this.lookupBypassed = lookupBypassed;
            this.reason = reason;
            this.officialName = officialName;
            this.officialUuid = officialUuid;
        }

        public static PremiumResult valid(String officialName, UUID officialUuid) {
            return new PremiumResult(true, false, "OK", officialName, officialUuid);
        }

        public static PremiumResult validBypass(String reason) {
            return new PremiumResult(true, true, reason, null, null);
        }

        public static PremiumResult invalid(String reason) {
            return new PremiumResult(false, false, reason, null, null);
        }

        public boolean isValid() { return valid; }
        public boolean isLookupBypassed() { return lookupBypassed; }
        public String getReason() { return reason; }
        public String getOfficialName() { return officialName; }
        public UUID getOfficialUuid() { return officialUuid; }
    }
}

package org.ipsecuz.opprotection.listener;

import com.destroystokyo.paper.event.player.PlayerHandshakeEvent;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.ChatColor;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.security.PreAuthService;
import org.ipsecuz.opprotection.storage.SecurityDataStore;
import org.ipsecuz.opprotection.utils.GeoIPChecker;

import java.net.IDN;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.HashSet;

/** Pre-login security checks. Never cancels Paper's handshake pipeline by default. */
public final class PacketIpCheck implements Listener {
    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();
    private final OPProtection plugin;
    private final GeoIPChecker geoIP;
    private volatile boolean domainWhitelistEnabled;
    private volatile boolean allowSubdomains;
    private volatile boolean strictProxyEnabled;
    private volatile boolean blockWhenProxyRulesEmpty;
    private volatile Set<String> allowedDomains = Set.of();
    private volatile List<String> allowedProxyRules = List.of();
    private volatile String primaryDomain = "server chính thức";
    private volatile String proxyBlockedMessage = "&cProxy/IP kết nối không hợp lệ.";
    private volatile String geoIpBlockMessage = "&cKhu vực của bạn không được phép truy cập server.";
    private volatile String domainKickMessage = "&cBạn phải kết nối qua domain chính thức: &f%domain%";
    private volatile String noDomainMessage = "&cKhông xác định được domain kết nối.";
    private volatile String premiumKickMessage = "&cTài khoản quản trị phải đăng nhập bằng premium đã xác thực.";

    public PacketIpCheck(OPProtection plugin) {
        this.plugin = plugin;
        this.geoIP = new GeoIPChecker(plugin);
        reload();
    }

    public void reload() {
        geoIP.reload();
        this.domainWhitelistEnabled = plugin.getConfig().getBoolean("domain-whitelist.enabled", false);
        this.allowSubdomains = plugin.getConfig().getBoolean("domain-whitelist.allow-subdomains", false);
        this.strictProxyEnabled = plugin.getConfig().getBoolean("domain-whitelist.strict-proxy-ip.enabled", true);
        this.blockWhenProxyRulesEmpty = plugin.getConfig().getBoolean(
                "domain-whitelist.strict-proxy-ip.block-when-empty", true);

        Set<String> domains = new HashSet<>();
        List<String> configuredDomains = plugin.getConfig().getStringList("domain-whitelist.allowed-domains");
        for (String configured : configuredDomains) {
            String normalized = normalizeHost(configured);
            if (!normalized.isEmpty()) domains.add(normalized);
        }
        this.allowedDomains = Set.copyOf(domains);
        this.primaryDomain = configuredDomains.isEmpty() ? "server chính thức" : configuredDomains.get(0);

        List<String> proxyRules = new ArrayList<>();
        for (String configured : plugin.getConfig().getStringList(
                "domain-whitelist.strict-proxy-ip.allowed-proxy-ips")) {
            if (configured != null && !configured.isBlank()) proxyRules.add(configured.trim());
        }
        this.allowedProxyRules = List.copyOf(proxyRules);
        this.proxyBlockedMessage = plugin.getConfig().getString("domain-whitelist.messages.proxy-blocked",
                "&cProxy/IP kết nối không hợp lệ. Vui lòng vào qua proxy chính thức.");
        this.geoIpBlockMessage = plugin.getConfig().getString("geoip.block-message",
                "&cKhu vực của bạn không được phép truy cập server.");
        this.domainKickMessage = plugin.getConfig().getString("domain-whitelist.messages.kick-message",
                "&cBạn phải kết nối qua domain chính thức: &f%domain%");
        this.noDomainMessage = plugin.getConfig().getString("domain-whitelist.messages.no-domain-detected",
                "&cKhông xác định được domain kết nối. Hãy dùng domain chính thức.");
        this.premiumKickMessage = plugin.getConfig().getString("premium-auth.messages.kick-cracked-spoof",
                "&cTài khoản quản trị phải đăng nhập bằng premium đã xác thực.");
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onHandshake(PlayerHandshakeEvent event) {
        if (!domainWhitelistEnabled) return;
        String socketIp = normalizeIp(event.getOriginalSocketAddressHostname());
        if (!proxyAllowed(socketIp)) {
            event.setFailed(true);
            event.failMessage(LEGACY.deserialize(proxyBlockedMessage));
            plugin.getAuditLog().write("PROXY_IP_BLOCK", "<handshake>", "", socketIp,
                    "serverHostname=" + safe(event.getServerHostname()));
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (event.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) return;
        String ip = normalizeIp(event.getAddress().getHostAddress());

        GeoIPChecker.Result geo = geoIP.check(ip);
        if (!geo.allowed()) {
            deny(event, geoIpBlockMessage);
            plugin.getAuditLog().write("GEOIP_BLOCK", event.getName(), event.getUniqueId().toString(), ip, geo.countryCode());
            return;
        }

        if (!hostnameAllowed(event.getHostname())) {
            String template = normalizeHost(event.getHostname()).isEmpty() ? noDomainMessage : domainKickMessage;
            deny(event, template.replace("%domain%", primaryDomain));
            plugin.getAuditLog().write("DOMAIN_BLOCK", event.getName(), event.getUniqueId().toString(), ip,
                    "hostname=" + safe(event.getHostname()));
            return;
        }

        PreAuthService.Decision preAuth = plugin.getPreAuthService().preLogin(event.getName(), event.getUniqueId());
        if (!preAuth.allowed()) {
            deny(event, premiumKickMessage);
            plugin.getAuditLog().write("PREAUTH_BLOCK", event.getName(), event.getUniqueId().toString(), ip, preAuth.reason());
            return;
        }
        if (preAuth.warning()) {
            plugin.getLogger().warning("[PreAuth] Phiên không có bằng chứng Premium mạnh: "
                    + event.getName() + " | " + preAuth.reason());
        }

        plugin.getSecurityDataStore().claimLegacyTrustedIp(event.getName(), event.getUniqueId());
        SecurityDataStore.IdentityCheck identity = plugin.getSecurityDataStore().recordIdentity(event.getName(), event.getUniqueId(), ip);
        if (identity.status() == SecurityDataStore.IdentityStatus.MISMATCH) {
            deny(event, "&cUUID của tài khoản không khớp dữ liệu bảo mật. Vui lòng liên hệ quản trị viên.");
            plugin.getAuditLog().write("UUID_MISMATCH", event.getName(), event.getUniqueId().toString(), ip,
                    "expected=" + identity.expectedUuid());
            if (plugin.isDiscordEnabled()) {
                String playerName = event.getName();
                String joinedUuid = event.getUniqueId().toString();
                plugin.getSchedulerService().runGlobal(() -> {
                    if (plugin.isDiscordEnabled()) {
                        plugin.getDiscord().sendSpoofAlertEmbed(playerName, ip, "unknown", joinedUuid, "UUID mismatch");
                    }
                });
            }
        }
    }

    private void deny(AsyncPlayerPreLoginEvent event, String message) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, color(message));
    }

    private boolean hostnameAllowed(String raw) {
        if (!domainWhitelistEnabled) return true;
        String host = normalizeHost(raw);
        if (host.isEmpty()) return false;
        boolean subdomains = allowSubdomains;
        for (String allowed : allowedDomains) {
            if (host.equals(allowed) || (subdomains && host.endsWith('.' + allowed))) return true;
        }
        return false;
    }

    private boolean proxyAllowed(String ip) {
        if (!strictProxyEnabled) return true;
        List<String> rules = allowedProxyRules;
        if (rules.isEmpty()) return !blockWhenProxyRulesEmpty;
        for (String rule : rules) if (matchesIpRule(ip, rule)) return true;
        return false;
    }

    private boolean matchesIpRule(String ip, String rawRule) {
        if (rawRule == null) return false;
        String rule = stripComment(rawRule);
        if (rule.endsWith(".*")) return ip.startsWith(rule.substring(0, rule.length() - 1));
        if (rule.contains("/")) return cidrMatch(ip, rule);
        return normalizeIp(rule).equals(ip);
    }

    private boolean cidrMatch(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/", 2);
            byte[] address = InetAddress.getByName(ip).getAddress();
            byte[] network = InetAddress.getByName(normalizeIp(parts[0])).getAddress();
            if (address.length != network.length) return false;
            int prefix = Integer.parseInt(parts[1]);
            if (prefix < 0 || prefix > address.length * 8) return false;
            for (int bit = 0; bit < prefix; bit++) {
                int mask = 1 << (7 - bit % 8);
                if ((address[bit / 8] & mask) != (network[bit / 8] & mask)) return false;
            }
            return true;
        } catch (Exception ignored) { return false; }
    }

    private String normalizeHost(String raw) {
        if (raw == null) return "";
        String host = raw;
        int nul = host.indexOf('\0');
        if (nul >= 0) host = host.substring(0, nul);
        host = host.trim().toLowerCase(Locale.ROOT);
        if (host.startsWith("[")) {
            int end = host.indexOf(']');
            if (end > 0) host = host.substring(1, end);
        } else {
            int colon = host.lastIndexOf(':');
            if (colon > 0 && host.indexOf(':') == colon && host.substring(colon + 1).matches("\\d+")) host = host.substring(0, colon);
        }
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        try { return IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT); }
        catch (IllegalArgumentException ignored) { return ""; }
    }

    private String normalizeIp(String raw) {
        if (raw == null) return "";
        String value = stripComment(raw.trim());
        if (value.startsWith("/")) value = value.substring(1);
        if (value.startsWith("[")) {
            int end = value.indexOf(']');
            if (end > 0) value = value.substring(1, end);
        } else {
            int colon = value.lastIndexOf(':');
            if (colon > 0 && value.indexOf(':') == colon && value.substring(colon + 1).matches("\\d+")) value = value.substring(0, colon);
        }
        try { return InetAddress.getByName(value).getHostAddress(); }
        catch (Exception ignored) { return value; }
    }

    private String stripComment(String value) {
        int index = value.indexOf('#');
        return (index >= 0 ? value.substring(0, index) : value).trim();
    }
    private String color(String text) { return ChatColor.translateAlternateColorCodes('&', text == null ? "" : text); }
    private String safe(String text) { return text == null ? "" : text.replace('\n', ' ').replace('\r', ' '); }
}

package org.ipsecuz.opprotection.listener;

import com.destroystokyo.paper.event.player.PlayerHandshakeEvent;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.ChatColor;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerLoginEvent;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.security.PremiumAccountChecker.PremiumResult;
import org.ipsecuz.opprotection.utils.GeoIPChecker;

import java.io.File;
import java.io.IOException;
import java.net.IDN;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class PacketIpCheck implements Listener {
    private static final LegacyComponentSerializer LEGACY_AMPERSAND = LegacyComponentSerializer.legacyAmpersand();

    private final OPProtection plugin;
    private final boolean ipForwardingEnabled;
    private final GeoIPChecker geoIPChecker;
    private final File uuidPlayersFile;
    private final File uuidLogFile;
    private final Object uuidFileLock = new Object();

    public PacketIpCheck(OPProtection plugin, boolean ipForwardingEnabled) {
        this.plugin = plugin;
        this.ipForwardingEnabled = ipForwardingEnabled;
        this.geoIPChecker = new GeoIPChecker(plugin);

        File uuidFolder = new File(plugin.getDataFolder(), "uuid");
        if (!uuidFolder.exists()) uuidFolder.mkdirs();
        this.uuidPlayersFile = new File(uuidFolder, "players.yml");
        this.uuidLogFile = new File(uuidFolder, "log.yml");

        try {
            if (!this.uuidPlayersFile.exists()) this.uuidPlayersFile.createNewFile();
            if (!this.uuidLogFile.exists()) this.uuidLogFile.createNewFile();
        } catch (IOException e) {
            plugin.getLogger().warning("Could not create UUID files: " + e.getMessage());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void preserveDefaultPlayerHandshake(PlayerHandshakeEvent event) {
        event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPlayerHandshake(PlayerHandshakeEvent event) {
        if (!plugin.getConfig().getBoolean("domain-whitelist.enabled", false)) return;

        String rawProxyIp = normalizeIpAddress(event.getOriginalSocketAddressHostname());
        if (!isProxyAddressAllowed(rawProxyIp)) {
            String kickMsg = plugin.getConfig().getString(
                    "domain-whitelist.messages.proxy-blocked",
                    "&cProxy/IP kết nối không hợp lệ. Vui lòng vào server qua proxy chính thức.");
            blockHandshake(event, kickMsg);
            addLog("PROXY_IP_BLOCK", "<handshake>", "unknown", rawProxyIp,
                    "Raw socket IP is not whitelisted; serverHostname=" + safe(event.getServerHostname())
                            + "; originalHandshake=" + safe(event.getOriginalHandshake()));
            return;
        }

    }

    @EventHandler
    public void onAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        String clientIp = normalizeIpAddress(event.getAddress().getHostAddress());

        if (!this.geoIPChecker.isCountryAllowed(clientIp)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    color(this.plugin.getConfig().getString("geoip.block-message", "&cQuốc gia của bạn không được phép!")));
            return;
        }

        if (!isHostnameAllowed(event.getHostname())) {
            List<String> allowedDomains = this.plugin.getConfig().getStringList("domain-whitelist.allowed-domains");
            String firstDomain = allowedDomains.isEmpty() ? "Unknown" : allowedDomains.get(0);
            String key = normalizeHost(event.getHostname()).isEmpty() ? "domain-whitelist.messages.no-domain-detected" : "domain-whitelist.messages.kick-message";
            String kickMsg = color(this.plugin.getConfig().getString(key,
                    "&cBạn không được phép kết nối trực tiếp vào server này!\n&eVui lòng sử dụng domain chính thống: &f%domain%"));
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, kickMsg.replace("%domain%", firstDomain));
            addLog("DOMAIN_BLOCK", event.getName(), event.getUniqueId().toString(), clientIp, "Hostname=" + event.getHostname());
            return;
        }

        if (!checkPremiumForProtectedOp(event, clientIp)) {
            return;
        }

        checkAndRecordUuid(event, clientIp);
    }

    @EventHandler
    public void onPlayerLogin(PlayerLoginEvent event) {
        if (event.getResult() != PlayerLoginEvent.Result.ALLOWED) return;
        if (!this.ipForwardingEnabled || event.getRealAddress() == null) return;
        String realIp = normalizeIpAddress(event.getRealAddress().getHostAddress());
        plugin.getAsyncExecutor().submit(() -> updateStoredIp(event.getPlayer().getName(), realIp));
    }

    private void blockHandshake(PlayerHandshakeEvent event, String legacyMessage) {
        event.setCancelled(false);
        event.setFailed(true);
        event.failMessage(LEGACY_AMPERSAND.deserialize(legacyMessage == null ? "" : legacyMessage));
    }

    private boolean checkPremiumForProtectedOp(AsyncPlayerPreLoginEvent event, String ip) {
        if (!plugin.getConfig().getBoolean("premium-auth.enabled", false)) return true;
        if (!isOpWhitelisted(event.getName())) return true;

        PremiumResult result = plugin.getPremiumAccountChecker().check(event.getName(), event.getUniqueId());
        if (!result.isValid()) {
            String kickMsg = buildSafePremiumKickMessage();
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, kickMsg);
            addLog("PREMIUM_AUTH_BLOCK", event.getName(), event.getUniqueId().toString(), ip, result.getReason());
            return false;
        }

        boolean autoBypass2FA = plugin.getConfig().getBoolean("premium-auth.op-whitelist-premium-auto-bypass-2fa", false);
        if (autoBypass2FA && !result.isLookupBypassed()) {
            plugin.markPremium2FABypass(event.getUniqueId());
        } else {
            plugin.clearPremium2FABypass(event.getUniqueId());
        }
        addLog("PREMIUM_AUTH_OK", event.getName(), event.getUniqueId().toString(), ip,
                "Official=" + result.getOfficialName() + "/" + result.getOfficialUuid() + ", autoBypass2FA=" + autoBypass2FA);
        return true;
    }

    private String buildSafePremiumKickMessage() {
        String configured = plugin.getConfig().getString("premium-auth.messages.kick-cracked-spoof",
                "&cBạn không phải là tài khoản premium, vui lòng đăng nhập bằng premium");
        if (configured == null || configured.isBlank()) {
            configured = "&cBạn không phải là tài khoản premium, vui lòng đăng nhập bằng premium";
        }

        // Never expose internal verification details such as official/joined UUIDs to the player.
        StringBuilder safe = new StringBuilder();
        for (String line : configured.split("\\r?\\n")) {
            String lower = ChatColor.stripColor(color(line)).toLowerCase(Locale.ROOT);
            if (line.contains("%reason%") || lower.contains("uuid mismatch") || lower.contains("official=") || lower.contains("joined=")) {
                continue;
            }
            if (!line.isBlank()) {
                if (safe.length() > 0) safe.append('\n');
                safe.append(line);
            }
        }

        if (safe.length() == 0) {
            safe.append("&cBạn không phải là tài khoản premium, vui lòng đăng nhập bằng premium");
        }
        return color(safe.toString());
    }

    private void checkAndRecordUuid(AsyncPlayerPreLoginEvent event, String ip) {
        synchronized (uuidFileLock) {
            try {
                YamlConfiguration yml = YamlConfiguration.loadConfiguration(this.uuidPlayersFile);
                String path = "players." + event.getName();
                String uuid = event.getUniqueId().toString();
                long now = System.currentTimeMillis();

                if (!yml.contains(path)) {
                    yml.set(path + ".uuid", uuid);
                    yml.set(path + ".ip", ip);
                    yml.set(path + ".firstJoin", now);
                    yml.set(path + ".lastJoin", now);
                    yml.save(this.uuidPlayersFile);
                    addLog("NEW_USER", event.getName(), uuid, ip, "First join");
                    return;
                }

                String storedUuid = yml.getString(path + ".uuid");
                if (storedUuid != null && !storedUuid.equalsIgnoreCase(uuid)) {
                    addLog("UUID_MISMATCH", event.getName(), uuid, ip, "UUID mismatch expected " + storedUuid);
                    if (this.plugin.isDiscordEnabled()) {
                        this.plugin.getDiscord().sendSpoofAlertEmbed(event.getName(), ip, "Unknown", storedUuid, "UUID Spoof Detected");
                    }
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, color("&eUUID của bạn không khớp với dữ liệu hệ thống!\n&eVui lòng liên hệ Admin qua Discord ngay lập tức."));
                    return;
                }

                yml.set(path + ".lastJoin", now);
                yml.set(path + ".ip", ip);
                yml.save(this.uuidPlayersFile);
                addLog("JOIN", event.getName(), uuid, ip, "Đăng nhập lại");
            } catch (IOException e) {
                this.plugin.getLogger().warning("Failed to save UUID data: " + e.getMessage());
            }
        }
    }

    private void updateStoredIp(String playerName, String realIp) {
        synchronized (uuidFileLock) {
            try {
                YamlConfiguration yml = YamlConfiguration.loadConfiguration(this.uuidPlayersFile);
                String path = "players." + playerName;
                if (yml.contains(path)) {
                    yml.set(path + ".realIp", realIp);
                    yml.save(this.uuidPlayersFile);
                }
            } catch (IOException e) {
                this.plugin.getLogger().warning("Failed to update real IP: " + e.getMessage());
            }
        }
    }

    private boolean isHostnameAllowed(String rawHostname) {
        if (!plugin.getConfig().getBoolean("domain-whitelist.enabled", false)) return true;
        String hostname = normalizeHost(rawHostname);
        if (hostname.isEmpty()) return false;
        for (String domain : plugin.getConfig().getStringList("domain-whitelist.allowed-domains")) {
            String allowed = normalizeHost(domain);
            if (allowed.isEmpty()) continue;
            if (hostname.equals(allowed)) return true;
            if (plugin.getConfig().getBoolean("domain-whitelist.allow-subdomains", false) && hostname.endsWith("." + allowed)) return true;
        }
        return false;
    }

    private String normalizeHost(String raw) {
        if (raw == null) return "";
        String host = raw;
        int nul = host.indexOf('\0');
        if (nul >= 0) host = host.substring(0, nul);
        host = host.trim().toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.startsWith("[")) {
            int end = host.indexOf(']');
            if (end > 0) host = host.substring(1, end);
        } else {
            int colon = host.lastIndexOf(':');
            if (colon > -1 && host.indexOf(':') == colon && isAllDigits(host.substring(colon + 1))) {
                host = host.substring(0, colon);
            }
        }
        try {
            host = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException ignored) {
            return "";
        }
        return host;
    }

    private boolean isProxyAddressAllowed(String ip) {
        if (!plugin.getConfig().getBoolean("domain-whitelist.enabled", false)) return true;
        if (!plugin.getConfig().getBoolean("domain-whitelist.strict-proxy-ip.enabled", true)) return true;

        String normalizedIp = normalizeIpAddress(ip);
        if (normalizedIp.isEmpty()) return false;

        List<String> allowed = plugin.getConfig().getStringList("domain-whitelist.strict-proxy-ip.allowed-proxy-ips");
        if (allowed.isEmpty()) {
            return !plugin.getConfig().getBoolean("domain-whitelist.strict-proxy-ip.block-when-empty", true);
        }
        for (String entry : allowed) {
            if (matchesIpRule(normalizedIp, entry)) return true;
        }
        return false;
    }

    private boolean matchesIpRule(String ip, String rule) {
        if (rule == null || rule.trim().isEmpty()) return false;
        String cleanRule = stripInlineComment(rule.trim());
        if (cleanRule.isEmpty()) return false;

        if (cleanRule.endsWith(".*")) {
            String prefix = cleanRule.substring(0, cleanRule.length() - 1);
            return ip.startsWith(prefix);
        }

        if (cleanRule.contains("/")) {
            return cidrMatch(ip, cleanRule);
        }

        String normalizedRule = normalizeIpAddress(cleanRule);
        return !normalizedRule.isEmpty() && normalizedRule.equals(ip);
    }

    private boolean cidrMatch(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/", 2);
            if (parts.length != 2) return false;

            String networkPart = normalizeIpAddress(parts[0]);
            if (networkPart.isEmpty()) return false;

            byte[] address = InetAddress.getByName(ip).getAddress();
            byte[] network = InetAddress.getByName(networkPart).getAddress();
            if (address.length != network.length) return false;

            int prefix = Integer.parseInt(parts[1].trim());
            int maxPrefix = address.length * 8;
            if (prefix < 0 || prefix > maxPrefix) return false;

            int fullBytes = prefix / 8;
            int remainingBits = prefix % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != network[i]) return false;
            }
            if (remainingBits == 0) return true;
            if (fullBytes >= address.length) return true;
            int mask = 0xFF << (8 - remainingBits);
            return (address[fullBytes] & mask) == (network[fullBytes] & mask);
        } catch (Exception ignored) {
            return false;
        }
    }

    private String normalizeIpAddress(String raw) {
        if (raw == null) return "";
        String value = stripInlineComment(raw.trim());
        if (value.isEmpty()) return "";

        if (value.startsWith("/")) value = value.substring(1);

        if (value.startsWith("[")) {
            int end = value.indexOf(']');
            if (end > 0) value = value.substring(1, end);
        } else {
            int colon = value.lastIndexOf(':');
            if (colon > -1 && value.indexOf(':') == colon && isAllDigits(value.substring(colon + 1))) {
                value = value.substring(0, colon);
            }
        }

        try {
            return InetAddress.getByName(value).getHostAddress();
        } catch (Exception ignored) {
            return value;
        }
    }

    private String stripInlineComment(String value) {
        int comment = value.indexOf('#');
        if (comment >= 0) value = value.substring(0, comment);
        return value.trim();
    }

    private boolean isAllDigits(String value) {
        if (value == null || value.isEmpty()) return false;
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) return false;
        }
        return true;
    }

    private boolean isOpWhitelisted(String name) {
        Set<String> names = new HashSet<>(plugin.getConfig().getStringList("op-whitelist"));
        for (String n : names) if (n.equalsIgnoreCase(name)) return true;
        return false;
    }

    private String color(String text) {
        return ChatColor.translateAlternateColorCodes('&', text == null ? "" : text);
    }

    private String safe(String text) {
        if (text == null) return "";
        return text.replace('\n', ' ').replace('\r', ' ');
    }

    private void addLog(String type, String player, String uuid, String ip, String detail) {
        synchronized (uuidFileLock) {
            try {
                YamlConfiguration logYml = YamlConfiguration.loadConfiguration(this.uuidLogFile);
                List<String> logs = logYml.getStringList("logs");
                String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                logs.add("[" + time + "] [" + type + "] Player=" + player + " | UUID=" + uuid + " | IP=" + ip + " | Detail=" + detail);
                logYml.set("logs", logs);
                logYml.save(this.uuidLogFile);
            } catch (IOException e) {
                this.plugin.getLogger().warning("Failed to write security log: " + e.getMessage());
            }
        }
    }
}

package org.ipsecuz.opprotection.managers;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;

public class IPManager {
    private final OPProtection plugin;
    private final Map<String, String> playerIPs;
    private final boolean geoIpEnabled;
    private final Set<String> allowedCountries;
    private final String blockMessage;

    public IPManager(OPProtection plugin) {
        this.plugin = plugin;
        this.playerIPs = new HashMap<String, String>();
        FileConfiguration config = plugin.getConfig();
        this.geoIpEnabled = config.getBoolean("geoip.enabled", false);
        this.allowedCountries = Set.copyOf(config.getStringList("geoip.allowed-countries"));
        this.blockMessage = config.getString("geoip.block-message", "&cYour country is not allowed on this server!");
        this.loadIPs();
    }

    public void loadIPs() {
        FileConfiguration cfg = this.plugin.getConfig();
        this.playerIPs.clear();
        if (cfg.getConfigurationSection("player-ips") != null) {
            for (String player : cfg.getConfigurationSection("player-ips").getKeys(false)) {
                this.playerIPs.put(player, cfg.getString("player-ips." + player, "unknown"));
            }
        }
    }

    public void saveIPs() {
        FileConfiguration cfg = this.plugin.getConfig();
        cfg.set("player-ips", null);
        for (Map.Entry<String, String> entry : this.playerIPs.entrySet()) {
            cfg.set("player-ips." + entry.getKey(), (Object)entry.getValue());
        }
        this.plugin.saveConfig();
    }

    public void addOrUpdateIP(Player p) {
        String ip = p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "unknown";
        this.playerIPs.put(p.getName(), ip);
        this.saveIPs();
    }

    public boolean isIPAllowed(Player p) {
        String countryCode;
        String ip;
        String string = ip = p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "unknown";
        if (this.geoIpEnabled && (countryCode = this.fetchCountryCodeSync(ip)) != null && !this.allowedCountries.contains(countryCode)) {
            this.plugin.getLogger().warning(p.getName() + " (" + ip + ") \u0111\u00e3 b\u1ecb ch\u1eb7n do qu\u1ed1c gia: " + countryCode);
            return false;
        }
        String storedIP = this.getIP(p.getName());
        if (!ip.equals(storedIP) && !storedIP.equals("unknown")) {
            this.plugin.msg(p, "op_verification_ip_mismatch");
            return false;
        }
        return true;
    }

    public void resetIP(String playerName) {
        this.playerIPs.put(playerName, "unknown");
        this.saveIPs();
    }

    public String getIP(String playerName) {
        return this.playerIPs.getOrDefault(playerName, "unknown");
    }

    public String getBlockMessage() {
        return this.blockMessage;
    }

    private String fetchCountryCodeSync(String ip) {
        try {
            URL url = new URL("http://ip-api.com/json/" + ip + "?fields=countryCode");
            HttpURLConnection connection = (HttpURLConnection)url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            if (connection.getResponseCode() != 200) return null;
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));){
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                String jsonResponse = response.toString();
                if (!jsonResponse.contains("\"countryCode\":\"")) return null;
                String string = jsonResponse.split("\"countryCode\":\"")[1].split("\"")[0];
                return string;
            }
        }
        catch (Exception e) {
            this.plugin.getLogger().log(Level.WARNING, "Failed to fetch country for IP: " + ip + " - " + e.getMessage());
        }
        return null;
    }

    public void onPlayerJoin(Player player) {
    }

    public void updatePlayerIP(Player player) {
        String ip = player.getAddress().getHostString();
        this.plugin.getConfig().set("data." + player.getUniqueId() + ".ip", ip);
        this.plugin.saveConfig();
    }

}

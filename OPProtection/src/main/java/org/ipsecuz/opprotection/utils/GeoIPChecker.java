package org.ipsecuz.opprotection.utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.List;
import org.ipsecuz.opprotection.OPProtection;

public class GeoIPChecker {
    private final OPProtection plugin;

    public GeoIPChecker(OPProtection plugin) {
        this.plugin = plugin;
    }

    public boolean isCountryAllowed(String ip) {
        try {
            if (!this.plugin.getConfig().getBoolean("geoip.enabled", false)) {
                return true;
            }

            URL url = new URL("http://ip-api.com/json/" + ip + "?fields=status,countryCode");
            BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
            String response = reader.readLine();
            reader.close();

            this.plugin.getLogger().info("=== [GeoIP CHECK] ===");
            this.plugin.getLogger().info("Checking IP: " + ip);

            if (response.contains("\"countryCode\":\"")) {
                String countryCode = response.split("\"countryCode\":\"")[1].split("\"")[0];
                List allowedCountries = this.plugin.getConfig().getStringList("geoip.allowed-countries");
                boolean isAllowed = allowedCountries.contains(countryCode);
                this.plugin.getLogger().info("Detected Country: " + countryCode);

                return isAllowed;
            } else {
                this.plugin.getLogger().warning("GeoIP response không chứa countryCode (Có thể bị lỗi hoặc limit API).");
            }
        }
        catch (Exception e) {
            this.plugin.getLogger().warning("GeoIP check failed: " + e.getMessage());
        }
        return true;
    }
}
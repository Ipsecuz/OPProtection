package org.ipsecuz.opprotection.utils;

import org.ipsecuz.opprotection.OPProtection;

public class ConfigCache {
    private final OPProtection plugin;

    public ConfigCache(OPProtection plugin) {
        this.plugin = plugin;
    }

    public void reload() {
        plugin.getLogger().info("Config cache reloaded.");
    }
}
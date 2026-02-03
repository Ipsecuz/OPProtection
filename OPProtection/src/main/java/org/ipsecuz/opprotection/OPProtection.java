package org.ipsecuz.opprotection;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.ipsecuz.opprotection.listener.CommandBlocker;
import org.ipsecuz.opprotection.listener.PacketIpCheck;
import org.ipsecuz.opprotection.listener.TabCompleteBlocker;
import org.ipsecuz.opprotection.command.CommandOPPass;
import org.ipsecuz.opprotection.command.CommandOPReload;
import org.ipsecuz.opprotection.discord.DiscordBot;
import org.ipsecuz.opprotection.managers.IPManager;
import org.ipsecuz.opprotection.managers.OpManager;
import org.ipsecuz.opprotection.utils.ConfigCache;

import java.io.File;
import java.util.*;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

public class OPProtection extends JavaPlugin {
    private OpManager opManager;
    private IPManager ipManager;
    private DiscordBot discordBot;
    private ConfigCache configCache;
    private FileConfiguration messagesConfig;
    private FileConfiguration embedConfig;
    private final ScheduledExecutorService asyncExecutor = Executors.newScheduledThreadPool(2);
    private volatile boolean needsConfigSave = false;

    @Override
    public void onEnable() {
        printLogo();
        long startTime = System.currentTimeMillis();

        saveDefaultConfig();
        loadMessagesConfig();
        loadEmbedsConfig();

        this.configCache = new ConfigCache(this);
        loadManagers();
        registerListeners();
        registerCommands();
        startAsyncConfigSaver();

        long loadTime = System.currentTimeMillis() - startTime;
        getLogger().info("§a✓ OPProtection enabled successfully in " + loadTime + "ms");
        getLogger().info("§aVersion: " + getDescription().getVersion());
    }

    @Override
    public void onDisable() {
        if (opManager != null) {
            opManager.cancelAllCountdowns();
            for (Player p : Bukkit.getOnlinePlayers()) {
                if (opManager.isLocked(p)) opManager.handleLogout(p);
            }
        }
        if (discordBot != null) discordBot.shutdown();
        if (needsConfigSave) super.saveConfig();

        asyncExecutor.shutdown();
        try {
            if (!asyncExecutor.awaitTermination(5, TimeUnit.SECONDS)) asyncExecutor.shutdownNow();
        } catch (InterruptedException e) {
            asyncExecutor.shutdownNow();
        }
        getLogger().info("§c✗ OPProtection disabled");
    }

    private void loadManagers() {
        Set<String> opWhitelist = new HashSet<>(getConfig().getStringList("op-whitelist"));
        String opPassword = getConfig().getString("op-password", "defaultpass");
        int passTimeout = getConfig().getInt("op-pass-timeout", 60);
        Set<String> disabledCommands = new HashSet<>(getConfig().getStringList("disabled-commands"));
        List<String> logoutActions = getConfig().getStringList("logout-actions");

        this.opManager = new OpManager(this, opWhitelist, opPassword, passTimeout, disabledCommands, logoutActions);
        this.ipManager = new IPManager(this);

        if (getConfig().getBoolean("discord.enabled", false)) {
            String token = getConfig().getString("discord.token");
            String channelId = getConfig().getString("discord.channel-id");
            if (token != null && !token.isEmpty() && channelId != null && !channelId.isEmpty()) {
                try {
                    this.discordBot = new DiscordBot(this, token, channelId);
                    getLogger().info("§aDiscord bot enabled");
                } catch (Exception e) {
                    getLogger().severe("§cFailed to start Discord Bot: " + e.getMessage());
                }
            }
        }
    }

    private void registerListeners() {
        boolean ipForwarding = getConfig().getBoolean("ip-forwarding", false);
        Bukkit.getPluginManager().registerEvents(new PacketIpCheck(this, ipForwarding), this);
        Bukkit.getPluginManager().registerEvents(new CommandBlocker(this), this);

        if (getConfig().getBoolean("tab-complete-block.enabled", true)) {
            try {
                Bukkit.getPluginManager().registerEvents(new TabCompleteBlocker(this), this);
            } catch (Exception e) {
                getLogger().warning("Could not enable TabCompleteBlocker (ProtocolLib missing?): " + e.getMessage());
            }
        }
    }

    private void registerCommands() {
        if (getCommand("oppass") != null) {
            getCommand("oppass").setExecutor(new CommandOPPass(this, opManager, ipManager));
        } else {
            getLogger().warning("Command 'oppass' not found in plugin.yml!");
        }

        if (getCommand("opreload") != null) {
            getCommand("opreload").setExecutor(new CommandOPReload(this));
        } else {
            getLogger().warning("Command 'opreload' not found in plugin.yml!");
        }

    }

    private void loadMessagesConfig() {
        File file = new File(getDataFolder(), "messages.yml");
        if (!file.exists()) saveResource("messages.yml", false);
        messagesConfig = YamlConfiguration.loadConfiguration(file);
    }

    private void loadEmbedsConfig() {
        File file = new File(getDataFolder(), "embed_discord.yml");
        if (!file.exists()) saveResource("embed_discord.yml", false);
        embedConfig = YamlConfiguration.loadConfiguration(file);
    }

    public void reloadValues() {

        reloadPlugin();
    }

    public void reloadPlugin() {
        reloadConfig();
        loadMessagesConfig();
        loadEmbedsConfig();
        configCache.reload();

        Set<String> opWhitelist = new HashSet<>(getConfig().getStringList("op-whitelist"));
        String opPassword = getConfig().getString("op-password", "defaultpass");
        int passTimeout = getConfig().getInt("op-pass-timeout", 60);
        Set<String> disabledCommands = new HashSet<>(getConfig().getStringList("disabled-commands"));
        List<String> logoutActions = getConfig().getStringList("logout-actions");

        opManager.reload(opWhitelist, opPassword, passTimeout, disabledCommands, logoutActions);
        getLogger().info("§aPlugin reloaded successfully");
    }

    private void startAsyncConfigSaver() {
        asyncExecutor.scheduleAtFixedRate(() -> {
            if (needsConfigSave) {
                try {
                    super.saveConfig();
                    needsConfigSave = false;
                } catch (Exception e) {
                    getLogger().log(Level.SEVERE, "Failed to auto-save config", e);
                }
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    public void saveConfigAsync() {
        needsConfigSave = true;
    }

    public String getMessage(String key) {
        // Lấy prefix từ config, nếu không có thì dùng mặc định
        String prefix = messagesConfig.getString("prefix", "&7[&cOPProtection&7] ");

        String msg = messagesConfig.getString(key);
        if (msg == null) {
            getLogger().warning("Missing message key: " + key);
            return "§cMissing message: " + key;
        }

        String translated = ChatColor.translateAlternateColorCodes('&', msg);
        if (key.contains("title") || key.contains("subtitle") ||
                key.contains("kick") || key.contains("instruction") ||
                key.contains("usage") || key.contains("broadcast")) {
            return translated;
        }

        return ChatColor.translateAlternateColorCodes('&', prefix) + translated;
    }

    public void msg(CommandSender sender, String key) {
        sender.sendMessage(getMessage(key));
    }

    public void msg(CommandSender sender, String key, Map<String, String> placeholders) {
        String msg = getMessage(key);
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            msg = msg.replace("%" + entry.getKey() + "%", entry.getValue());
        }
        sender.sendMessage(msg);
    }

    private void printLogo() {
        String[] logo = {
                "  ________ ____________________",
                " \\_____  \\\\______   \\______   \\",
                " /   |   \\|     ___/|     ___/",
                " /    |    \\    |    |    |",
                " \\_______  /____|    |____|",
                "         \\/"
        };
        for (String line : logo) {
            getLogger().info(line);
        }
    }

    public OpManager getOpManager() { return opManager; }
    public IPManager getIpManager() { return ipManager; }
    public DiscordBot getDiscord() { return discordBot; }
    public boolean isDiscordEnabled() { return discordBot != null; }
    public FileConfiguration getEmbedConfig() { return embedConfig; }
    public ConfigCache getConfigCache() { return configCache; }
    public ScheduledExecutorService getAsyncExecutor() { return asyncExecutor; }
}
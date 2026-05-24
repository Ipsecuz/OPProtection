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
import org.ipsecuz.opprotection.listener.F3BrandBlocker;
import org.ipsecuz.opprotection.listener.SecureOPPassCommandHider;
import org.ipsecuz.opprotection.listener.SecureOPPassPacketListener;
import org.ipsecuz.opprotection.command.CommandOPPass;
import org.ipsecuz.opprotection.command.CommandOPReload;
import org.ipsecuz.opprotection.command.CommandVerify;
import org.ipsecuz.opprotection.command.CommandOpVerify;
import org.ipsecuz.opprotection.discord.DiscordBot;
import org.ipsecuz.opprotection.discord.DiscordEventListener;
import org.ipsecuz.opprotection.managers.IPManager;
import org.ipsecuz.opprotection.managers.OpManager;
import org.ipsecuz.opprotection.managers.DiscordSyncModule;
import org.ipsecuz.opprotection.utils.ConfigCache;
import org.ipsecuz.opprotection.security.PremiumAccountChecker;
import org.ipsecuz.opprotection.security.PasswordHasher;

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
    private DiscordEventListener discordEventListener;
    private DiscordSyncModule discordSyncModule;
    private ConfigCache configCache;
    private FileConfiguration messagesConfig;
    private FileConfiguration embedConfig;
    private F3BrandBlocker f3BrandBlocker;
    private PremiumAccountChecker premiumAccountChecker;
    private CommandOPPass commandOPPass;
    private final ScheduledExecutorService asyncExecutor = Executors.newScheduledThreadPool(2);
    private volatile boolean needsConfigSave = false;
    private final Set<UUID> premium2FABypass = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private static final String RESET = "\u001B[0m";


    @Override
    public void onEnable() {
        printLogo();
        long startTime = System.currentTimeMillis();

        saveDefaultConfig();
        migrateLegacyGlobalPassword();
        loadMessagesConfig();
        loadEmbedsConfig();

        this.configCache = new ConfigCache(this);
        this.premiumAccountChecker = new PremiumAccountChecker(this);
        
        initializePacketEvents();
        
        loadManagers();
        registerCommands();
        registerListeners();
        startAsyncConfigSaver();

        long loadTime = System.currentTimeMillis() - startTime;
        getLogger().info("[OPProtection] Enabled successfully in " + loadTime + "ms");
        getLogger().info("[OPProtection] Version: " + getDescription().getVersion());
    }

    @Override
    public void onDisable() {
        if (opManager != null) {
            opManager.cancelAllCountdowns();
            for (Player p : Bukkit.getOnlinePlayers()) {
                if (opManager.isLocked(p)) opManager.handleLogout(p);
            }
        }
        if (discordEventListener != null) discordEventListener.shutdown();
        if (discordBot != null) discordBot.shutdown();
        if (needsConfigSave) super.saveConfig();

        asyncExecutor.shutdown();
        try {
            if (!asyncExecutor.awaitTermination(5, TimeUnit.SECONDS)) asyncExecutor.shutdownNow();
        } catch (InterruptedException e) {
            asyncExecutor.shutdownNow();
        }
        getLogger().info("[OPProtection] Disabled safely.");
    }

    private void loadManagers() {
        Set<String> opWhitelist = new HashSet<>(getConfig().getStringList("op-whitelist"));
        String opPassword = getConfig().getString("op-password", "defaultpass");
        int passTimeout = getConfig().getInt("pass-timeout", 60);
        Set<String> disabledCommands = new HashSet<>(getConfig().getStringList("disabled-commands"));
        List<String> logoutActions = getConfig().getStringList("logout-actions");

        this.opManager = new OpManager(this, opWhitelist, opPassword, passTimeout, disabledCommands, logoutActions);
        this.ipManager = new IPManager(this);
        this.discordSyncModule = new DiscordSyncModule(this);

        if (getConfig().getBoolean("discord.enabled", false)) {
            String token = getConfig().getString("discord.token");
            String channelId = getConfig().getString("discord.channel-id");
            if (token != null && !token.isEmpty() && channelId != null && !channelId.isEmpty()) {
                try {
                    this.discordBot = new DiscordBot(this, token, channelId);
                    getLogger().info("[OPProtection] Discord bot enabled.");
                    
                    if (discordBot.isConnected()) {
                        this.discordEventListener = new DiscordEventListener(this, discordBot.getClient());
                        getLogger().info("[OPProtection] Discord event listener registered.");
                    }
                } catch (Exception e) {
                    getLogger().severe("[OPProtection] Failed to start Discord bot: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    private void migrateLegacyGlobalPassword() {
        String stored = getConfig().getString("op-password", "");
        if (stored == null || stored.isBlank()) {
            getLogger().warning("[OPProtection] Global OP password is not configured. Use /oppass createpass <password> or /oppass resetpass in console.");
            return;
        }
        if (PasswordHasher.isStrongHash(stored)) {
            return;
        }
        try {
            getConfig().set("op-password", PasswordHasher.hash(stored));
            saveConfig();
            getLogger().warning("[OPProtection] Legacy plaintext op-password was migrated to a secure PBKDF2 hash. If you forgot it, use /oppass resetpass in console.");
        } catch (Exception e) {
            getLogger().severe("[OPProtection] Could not migrate legacy op-password: " + e.getMessage());
        }
    }

    private void initializePacketEvents() {
        try {
            if (com.github.retrooper.packetevents.PacketEvents.getAPI() != null) {
                getLogger().info("[OPProtection] PacketEvents detected.");
            }
        } catch (Throwable e) {
            getLogger().warning("[OPProtection] Failed to initialize PacketEvents: " + e.getMessage());
            getLogger().warning("[OPProtection] Packet-level features will fall back where possible.");
        }
    }

    private void registerListeners() {
        boolean ipForwarding = getConfig().getBoolean("ip-forwarding", false);
        if (this.commandOPPass != null) {
            Bukkit.getPluginManager().registerEvents(new SecureOPPassCommandHider(this, this.commandOPPass), this);
            if (getConfig().getBoolean("secure-command-input.hide-oppass-from-console-log", true)) {
                try {
                    com.github.retrooper.packetevents.PacketEvents.getAPI().getEventManager().registerListener(new SecureOPPassPacketListener(this));
                    getLogger().info("[OPProtection] Secure /oppass packet guard enabled.");
                } catch (Throwable e) {
                    getLogger().warning("[OPProtection] Could not enable packet-level /oppass guard. Bukkit fallback remains active: " + e.getMessage());
                }
            }
        }
        Bukkit.getPluginManager().registerEvents(new PacketIpCheck(this, ipForwarding), this);
        Bukkit.getPluginManager().registerEvents(new CommandBlocker(this), this);

        if (getConfig().getBoolean("tab-complete-block.enabled", true)) {
            try {
                Bukkit.getPluginManager().registerEvents(new TabCompleteBlocker(this), this);
                getLogger().info("[OPProtection] TabCompleteBlocker enabled.");
            } catch (Exception e) {
                getLogger().warning("Could not enable TabCompleteBlocker (PacketEvents missing?): " + e.getMessage());
            }
        }

        if (getConfig().getBoolean("f3-brand-spoof.enabled", false)) {
            try {
                this.f3BrandBlocker = new F3BrandBlocker(this);
                com.github.retrooper.packetevents.PacketEvents.getAPI().getEventManager().registerListener(this.f3BrandBlocker);
                getLogger().info("[OPProtection] F3 brand spoofer enabled.");
            } catch (Exception e) {
                getLogger().warning("Could not enable F3 Brand Spoofer: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private void registerCommands() {
        if (getCommand("oppass") != null) {
            this.commandOPPass = new CommandOPPass(this, opManager, ipManager);
            getCommand("oppass").setExecutor(this.commandOPPass);
        } else {
            getLogger().warning("Command 'oppass' not found in plugin.yml!");
        }

        if (getCommand("opreload") != null) {
            getCommand("opreload").setExecutor(new CommandOPReload(this));
        } else {
            getLogger().warning("Command 'opreload' not found in plugin.yml!");
        }

        if (getCommand("verify") != null) {
            getCommand("verify").setExecutor(new CommandVerify(this));
        } else {
            getLogger().warning("Command 'verify' not found in plugin.yml!");
        }

        if (getCommand("opverify") != null) {
            getCommand("opverify").setExecutor(new CommandOpVerify(this));
        } else {
            getLogger().warning("Command 'opverify' not found in plugin.yml!");
        }

    }

    public String gradient(String text, int r1, int g1, int b1, int r2, int g2, int b2) {
        StringBuilder sb = new StringBuilder();

        int length = text.length();
        for (int i = 0; i < length; i++) {
            float ratio = (float) i / (length - 1);

            int r = (int) (r1 + (r2 - r1) * ratio);
            int g = (int) (g1 + (g2 - g1) * ratio);
            int b = (int) (b1 + (b2 - b1) * ratio);

            sb.append("\u001B[38;2;")
            .append(r).append(";")
            .append(g).append(";")
            .append(b).append("m")
            .append(text.charAt(i));
        }

        sb.append(RESET);
        return sb.toString();
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
        int passTimeout = getConfig().getInt("pass-timeout", 60);
        Set<String> disabledCommands = new HashSet<>(getConfig().getStringList("disabled-commands"));
        List<String> logoutActions = getConfig().getStringList("logout-actions");

        opManager.reload(opWhitelist, opPassword, passTimeout, disabledCommands, logoutActions);
        discordSyncModule.reload();
            if (f3BrandBlocker != null) {
            f3BrandBlocker.reload();
        }
        getLogger().info("[OPProtection] Reload completed successfully.");
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
            getLogger().info(gradient(line, 255, 80, 80, 180, 0, 255));
        }
    }

    public OpManager getOpManager() { return opManager; }
    public IPManager getIpManager() { return ipManager; }
    public DiscordBot getDiscord() { return discordBot; }
    public boolean isDiscordEnabled() { return discordBot != null; }
    public FileConfiguration getEmbedConfig() { return embedConfig; }
    public ConfigCache getConfigCache() { return configCache; }
    public PremiumAccountChecker getPremiumAccountChecker() { return premiumAccountChecker; }
    public CommandOPPass getCommandOPPass() { return commandOPPass; }
    public DiscordSyncModule getDiscordSyncModule() { return discordSyncModule; }
    public ScheduledExecutorService getAsyncExecutor() { return asyncExecutor; }
    public void markPremium2FABypass(UUID uuid) { if (uuid != null) premium2FABypass.add(uuid); }
    public void clearPremium2FABypass(UUID uuid) { if (uuid != null) premium2FABypass.remove(uuid); }
    public boolean consumePremium2FABypass(UUID uuid) { return uuid != null && premium2FABypass.remove(uuid); }
    
    public boolean isFolia() {
        try {
            Class.forName("io.papermc.paper.threadedregions.RegionedServer");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}
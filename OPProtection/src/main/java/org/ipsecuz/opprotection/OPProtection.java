package org.ipsecuz.opprotection;

import com.github.retrooper.packetevents.PacketEvents;
import org.bstats.bukkit.Metrics;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.ipsecuz.opprotection.command.CommandOPPass;
import org.ipsecuz.opprotection.command.CommandOPReload;
import org.ipsecuz.opprotection.command.CommandOpVerify;
import org.ipsecuz.opprotection.command.CommandVerify;
import org.ipsecuz.opprotection.discord.DiscordBot;
import org.ipsecuz.opprotection.discord.DiscordEventListener;
import org.ipsecuz.opprotection.listener.CommandBlocker;
import org.ipsecuz.opprotection.listener.F3BrandBlocker;
import org.ipsecuz.opprotection.listener.OPListener;
import org.ipsecuz.opprotection.listener.PacketIpCheck;
import org.ipsecuz.opprotection.listener.SecureOPPassCommandHider;
import org.ipsecuz.opprotection.listener.SecureOPPassPacketListener;
import org.ipsecuz.opprotection.listener.TabCompleteBlocker;
import org.ipsecuz.opprotection.managers.DiscordSyncModule;
import org.ipsecuz.opprotection.managers.IPManager;
import org.ipsecuz.opprotection.managers.OpManager;
import org.ipsecuz.opprotection.scheduler.SchedulerService;
import org.ipsecuz.opprotection.security.PasswordHasher;
import org.ipsecuz.opprotection.security.PluginIntegrityMonitor;
import org.ipsecuz.opprotection.security.PreAuthService;
import org.ipsecuz.opprotection.security.PremiumAccountChecker;
import org.ipsecuz.opprotection.security.SecurityAuditLog;
import org.ipsecuz.opprotection.storage.SecurityDataStore;
import org.ipsecuz.opprotection.utils.ConfigCache;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class OPProtection extends JavaPlugin {
    private static final Pattern HEX_COLOR = Pattern.compile("(?i)&#([0-9a-f]{6})");
    private final ScheduledExecutorService asyncExecutor = Executors.newScheduledThreadPool(3, new SecurityThreadFactory());
    private final AtomicBoolean configSaveScheduled = new AtomicBoolean();
    private final Set<UUID> premium2FABypass = ConcurrentHashMap.newKeySet();

    private SchedulerService schedulerService;
    private SecurityDataStore securityDataStore;
    private SecurityAuditLog auditLog;
    private ConfigCache configCache;
    private PremiumAccountChecker premiumAccountChecker;
    private PreAuthService preAuthService;
    private PluginIntegrityMonitor integrityMonitor;
    private OpManager opManager;
    private IPManager ipManager;
    private DiscordSyncModule discordSyncModule;
    private volatile DiscordBot discordBot;
    private DiscordEventListener discordEventListener;
    private F3BrandBlocker f3BrandBlocker;
    private PacketIpCheck packetIpCheck;
    private TabCompleteBlocker tabCompleteBlocker;
    private CommandBlocker commandBlocker;
    private SecureOPPassPacketListener secureOPPassPacketListener;
    private CommandOPPass commandOPPass;
    private volatile FileConfiguration messagesConfig;
    private volatile FileConfiguration embedConfig;
    @SuppressWarnings("unused")
    private Metrics metrics;

    @Override
    public void onEnable() {
        long started = System.currentTimeMillis();
        saveDefaultConfig();

        this.schedulerService = new SchedulerService(this, asyncExecutor);
        printLogo();
        this.securityDataStore = new SecurityDataStore(this);
        if (securityDataStore.migrateLegacyConfig(getConfig())) saveConfig();
        migrateLegacyGlobalPassword();
        loadMessagesConfig();
        loadEmbedsConfig();

        this.auditLog = new SecurityAuditLog(this, schedulerService.asyncExecutor());
        this.configCache = new ConfigCache(this);
        this.premiumAccountChecker = new PremiumAccountChecker(this);
        this.preAuthService = new PreAuthService(this, premiumAccountChecker);

        if (!validatePacketEvents()) {
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }
        loadManagers();
        registerCommands();
        registerListeners();
        validateSecurityConfiguration();
        initializeMetrics();

        this.integrityMonitor = new PluginIntegrityMonitor(this);
        this.integrityMonitor.start();

        getLogger().info("Bật thành công trong " + (System.currentTimeMillis() - started) + "ms.");
        if (getConfig().getBoolean("premium-auth.enabled", false)) {
            getLogger().info("PremiumAuth mode: " + premiumAccountChecker.runtimeMode().name());
        }
    }

    @Override
    public void onDisable() {
        if (integrityMonitor != null) integrityMonitor.stop();
        if (opManager != null) opManager.cancelAllCountdowns();
        stopDiscord();
        if (metrics != null) {
            try { metrics.shutdown(); } catch (Throwable ignored) { }
        }
        if (securityDataStore != null) securityDataStore.flushBlocking();
        if (configSaveScheduled.get()) {
            try { saveConfig(); } catch (Exception ignored) { }
        }
        asyncExecutor.shutdown();
        try {
            if (!asyncExecutor.awaitTermination(5, TimeUnit.SECONDS)) asyncExecutor.shutdownNow();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            asyncExecutor.shutdownNow();
        }
        getLogger().info("[OPProtection] Đã tắt an toàn.");
    }

    private void loadManagers() {
        this.opManager = new OpManager(this, normalizedWhitelist(), getConfig().getString("op-password", ""),
                getConfig().getInt("pass-timeout", 60), normalizedCommands("disabled-commands"),
                getConfig().getStringList("logout-actions"));
        this.ipManager = new IPManager(this);
        this.discordSyncModule = new DiscordSyncModule(this);
        startDiscord();
    }

    private void stopDiscord() {
        if (discordEventListener != null) {
            discordEventListener.shutdown();
            discordEventListener = null;
        }
        if (discordBot != null) {
            discordBot.shutdown();
            discordBot = null;
        }
    }

    private void startDiscord() {
        if (!getConfig().getBoolean("discord.enabled", false)) return;
        String token = getConfig().getString("discord.token", "").trim();
        String channelId = getConfig().getString("discord.channel-id", "").trim();
        if (token.isBlank() || channelId.isBlank() || token.equals("YOUR_BOT_TOKEN") || channelId.equals("YOUR_CHANNEL_ID")) {
            getLogger().warning("[Discord] Đã bật nhưng token/channel-id chưa hợp lệ.");
            return;
        }
        try {
            this.discordBot = new DiscordBot(this, token, channelId);
            this.discordEventListener = new DiscordEventListener(this, discordBot.getClient());
        } catch (RuntimeException ex) {
            getLogger().severe("[Discord] Không thể khởi động bot: " + ex.getMessage());
        }
    }

    private void registerCommands() {
        this.commandOPPass = new CommandOPPass(this, opManager, ipManager);
        if (getCommand("oppass") != null) getCommand("oppass").setExecutor(commandOPPass);
        if (getCommand("opreload") != null) getCommand("opreload").setExecutor(new CommandOPReload(this));
        if (getCommand("verify") != null) getCommand("verify").setExecutor(new CommandVerify(this));
        if (getCommand("opverify") != null) getCommand("opverify").setExecutor(new CommandOpVerify(this));
    }

    private void registerListeners() {
        Bukkit.getPluginManager().registerEvents(new OPListener(this), this);
        this.packetIpCheck = new PacketIpCheck(this);
        Bukkit.getPluginManager().registerEvents(packetIpCheck, this);
        this.commandBlocker = new CommandBlocker(this);
        Bukkit.getPluginManager().registerEvents(commandBlocker, this);
        Bukkit.getPluginManager().registerEvents(new SecureOPPassCommandHider(this, commandOPPass), this);

        this.secureOPPassPacketListener = new SecureOPPassPacketListener(this);
        PacketEvents.getAPI().getEventManager().registerListener(secureOPPassPacketListener);
        this.tabCompleteBlocker = new TabCompleteBlocker(this);
        Bukkit.getPluginManager().registerEvents(tabCompleteBlocker, this);
        try { PacketEvents.getAPI().getEventManager().registerListener(tabCompleteBlocker); }
        catch (Throwable ex) { getLogger().warning("[TabComplete] Packet guard không hoạt động: " + ex.getMessage()); }

        this.f3BrandBlocker = new F3BrandBlocker(this);
        PacketEvents.getAPI().getEventManager().registerListener(f3BrandBlocker);
    }

    private boolean validatePacketEvents() {
        boolean enabled = java.util.Arrays.stream(Bukkit.getPluginManager().getPlugins())
                .anyMatch(candidate -> candidate.isEnabled() && candidate.getName().equalsIgnoreCase("packetevents"));
        if (!enabled) {
            getLogger().severe("[OPProtection] PacketEvents chưa được bật. Plugin tự tắt để tránh chạy thiếu lớp bảo vệ packet.");
        }
        return enabled;
    }


    private void validateSecurityConfiguration() {
        if (getConfig().getBoolean("domain-whitelist.enabled", false)) {
            boolean strictProxy = getConfig().getBoolean("domain-whitelist.strict-proxy-ip.enabled", true);
            List<String> proxyIps = getConfig().getStringList("domain-whitelist.strict-proxy-ip.allowed-proxy-ips");
            if (!strictProxy) {
                getLogger().warning("[Security] Domain whitelist không thể tự chứng minh proxy thật; nên bật strict-proxy-ip.");
            } else if (proxyIps.isEmpty()) {
                getLogger().warning("[Security] strict-proxy-ip đang bật nhưng allowed-proxy-ips trống; mọi kết nối sẽ bị chặn.");
            }
        }
        if (getConfig().getBoolean("premium-auth.enabled", false)) {
            PremiumAccountChecker.RuntimeMode mode = premiumAccountChecker.runtimeMode();
            switch (mode) {
                case ONLINE_MODE -> getLogger().info(
                        "[PreAuth] Chế độ ONLINE_MODE: UUID Premium được xác thực bởi server.");
                case PROXY_FORWARDED -> {
                    getLogger().info(
                            "[PreAuth] Chế độ PROXY_FORWARDED: yêu cầu proxy chuyển UUID Premium an toàn.");
                    if (!getConfig().getBoolean("domain-whitelist.strict-proxy-ip.enabled", true)) {
                        getLogger().warning("[PreAuth] strict-proxy-ip=false. Hãy khóa port backend bằng firewall "
                                + "hoặc bật strict-proxy-ip để giảm nguy cơ spoof forwarding.");
                    }
                }
                case STANDALONE_OFFLINE -> {
                    getLogger().warning("[PreAuth] Chế độ STANDALONE_OFFLINE: Mojang lookup chỉ xác nhận tên có hồ sơ Premium, "
                            + "không thể chứng minh client sở hữu tài khoản vì online-mode=false.");
                    getLogger().warning("[PreAuth] OPProtection sẽ bắt buộc password/console/Discord verification "
                            + "và không cho phép Premium tự bypass 2FA trong chế độ này.");
                }
            }
        }
        if (getConfig().getBoolean("discord-sync.enabled", false)
                && getConfig().getStringList("discord-sync.allowed-discord-user-ids").isEmpty()
                && getConfig().getStringList("discord-sync.allowed-discord-role-ids").isEmpty()) {
            getLogger().warning("[Discord-Sync] Chưa cấu hình approver user/role; không ai có thể nhấn nút phê duyệt.");
        }
    }

    private void initializeMetrics() {
        if (getConfig().getBoolean("metric", true)) {
            try {
                this.metrics = new Metrics(this, 32283);
                getLogger().info("[bStats] Metrics đã được khởi tạo với plugin ID 32283.");
            } catch (Throwable ex) {
                getLogger().warning("[bStats] Không thể khởi tạo metrics: " + ex.getMessage());
            }
        }
    }

    private void migrateLegacyGlobalPassword() {
        String stored = getConfig().getString("op-password", "");
        if (stored == null || stored.isBlank()) {
            getLogger().warning("[OPPass] Chưa có mật khẩu global. Hãy chạy từ console: /oppass createpass <mật-khẩu>");
            return;
        }
        if (PasswordHasher.isStrongHash(stored)) return;
        try {
            getConfig().set("op-password", PasswordHasher.hash(stored));
            saveConfig();
            getLogger().warning("[OPPass] Đã chuyển mật khẩu plaintext cũ sang PBKDF2 hash.");
        } catch (Exception ex) {
            getLogger().severe("[OPPass] Không thể migrate mật khẩu cũ: " + ex.getMessage());
        }
    }

    public void reloadValues() { reloadPlugin(); }

    public void reloadPlugin() {
        reloadConfig();
        migrateLegacyGlobalPassword();
        loadMessagesConfig();
        loadEmbedsConfig();
        configCache.reload();
        auditLog.reload();
        premiumAccountChecker.reload();
        preAuthService.reload();
        ipManager.reload();
        opManager.reload(normalizedWhitelist(), getConfig().getString("op-password", ""),
                getConfig().getInt("pass-timeout", 60), normalizedCommands("disabled-commands"),
                getConfig().getStringList("logout-actions"));
        discordSyncModule.reload();
        stopDiscord();
        startDiscord();
        if (tabCompleteBlocker != null) tabCompleteBlocker.reload();
        if (commandBlocker != null) commandBlocker.reload();
        if (secureOPPassPacketListener != null) secureOPPassPacketListener.reload();
        if (packetIpCheck != null) packetIpCheck.reload();
        if (f3BrandBlocker != null) f3BrandBlocker.reload();
        validateSecurityConfiguration();
        if (integrityMonitor != null) {
            integrityMonitor.stop();
            integrityMonitor.start();
        }
        getLogger().info("[OPProtection] Reload hoàn tất.");
    }

    public void saveConfigAsync() {
        if (!configSaveScheduled.compareAndSet(false, true)) return;
        schedulerService.runGlobalDelayed(() -> {
            try { saveConfig(); }
            finally { configSaveScheduled.set(false); }
        }, 20L);
    }

    private Set<String> normalizedWhitelist() {
        Set<String> values = new HashSet<>();
        for (String value : getConfig().getStringList("op-whitelist")) {
            if (value != null && !value.isBlank()) values.add(value.toLowerCase(Locale.ROOT));
        }
        return values;
    }

    private Set<String> normalizedCommands(String path) {
        Set<String> values = new HashSet<>();
        for (String value : getConfig().getStringList(path)) {
            if (value == null) continue;
            String command = value.trim().toLowerCase(Locale.ROOT);
            while (command.startsWith("/")) command = command.substring(1);
            if (!command.isBlank()) values.add(command);
        }
        return values;
    }

    private void loadMessagesConfig() {
        File file = new File(getDataFolder(), "messages.yml");
        if (!file.exists()) saveResource("messages.yml", false);
        this.messagesConfig = YamlConfiguration.loadConfiguration(file);
    }

    private void loadEmbedsConfig() {
        File file = new File(getDataFolder(), "embed_discord.yml");
        if (!file.exists()) saveResource("embed_discord.yml", false);
        this.embedConfig = YamlConfiguration.loadConfiguration(file);
    }

    public String getMessage(String key) {
        String prefix = messagesConfig.getString("prefix", "&8[&b&lOP&fProtection&8] &7");
        String message = messagesConfig.getString(key);
        if (message == null) {
            getLogger().warning("Thiếu message key: " + key);
            return ChatColor.RED + "Missing message: " + key;
        }
        String translated = colorize(message);
        if (key.contains("title") || key.contains("subtitle") || key.contains("kick")
                || key.contains("instruction") || key.contains("usage") || key.contains("broadcast")
                || key.startsWith("premium_auth_")) return translated;
        return colorize(prefix) + translated;
    }


    private String colorize(String input) {
        if (input == null || input.isEmpty()) return "";
        Matcher matcher = HEX_COLOR.matcher(input);
        StringBuffer output = new StringBuffer();
        while (matcher.find()) {
            String replacement;
            try { replacement = net.md_5.bungee.api.ChatColor.of("#" + matcher.group(1)).toString(); }
            catch (IllegalArgumentException ex) { replacement = matcher.group(); }
            matcher.appendReplacement(output, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(output);
        return ChatColor.translateAlternateColorCodes('&', output.toString());
    }

    public void msg(CommandSender sender, String key) { sender.sendMessage(getMessage(key)); }
    public void msg(CommandSender sender, String key, Map<String, String> placeholders) {
        String message = getMessage(key);
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            message = message.replace("%" + entry.getKey() + "%", entry.getValue());
        }
        sender.sendMessage(message);
    }

    private void printLogo() {
        String platform = schedulerService != null && schedulerService.isFolia() ? "folia" : "paper";
        getLogger().info("                            ");
        getLogger().info(" ,-----. ,------. ,------.  ");
        getLogger().info("'  .-.  '|  .--. '|  .--. ' ");
        getLogger().info("|  | |  ||  '--' ||  '--' | ");
        getLogger().info("'  '-'  '|  | --' |  | --'  ");
        getLogger().info(" `-----' `--'     `--'     ");
        getLogger().info("platform: " + platform + " version: " + getDescription().getVersion());
        getLogger().info("                   author: Ipsecuz_");
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
    public SchedulerService getSchedulerService() { return schedulerService; }
    public SecurityDataStore getSecurityDataStore() { return securityDataStore; }
    public SecurityAuditLog getAuditLog() { return auditLog; }
    public PreAuthService getPreAuthService() { return preAuthService; }
    public PluginIntegrityMonitor getIntegrityMonitor() { return integrityMonitor; }
    public boolean isFolia() { return schedulerService != null && schedulerService.isFolia(); }
    public void markPremium2FABypass(UUID uuid) { if (uuid != null) premium2FABypass.add(uuid); }
    public void clearPremium2FABypass(UUID uuid) { if (uuid != null) premium2FABypass.remove(uuid); }
    public boolean consumePremium2FABypass(UUID uuid) { return uuid != null && premium2FABypass.remove(uuid); }

    private static final class SecurityThreadFactory implements ThreadFactory {
        private int sequence;
        @Override public synchronized Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "OPProtection-Security-" + (++sequence));
            thread.setDaemon(true);
            thread.setUncaughtExceptionHandler((t, ex) -> ex.printStackTrace());
            return thread;
        }
    }
}

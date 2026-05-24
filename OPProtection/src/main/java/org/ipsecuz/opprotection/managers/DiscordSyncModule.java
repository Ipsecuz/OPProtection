package org.ipsecuz.opprotection.managers;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.ipsecuz.opprotection.OPProtection;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class DiscordSyncModule {
    private final OPProtection plugin;
    private final Set<String> commandRequiresSync = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Long> playerVerificationTime = new ConcurrentHashMap<>();
    private boolean moduleEnabled = false;
    private long verificationTimeoutMs;
    private String unauthorizedAction;
    private String messageCommandRequiresSync;
    private String messageVerifyRequired;
    private String messageDeop;
    private String messageShutdown;
    private String messageKick;

    public DiscordSyncModule(OPProtection plugin) {
        this.plugin = plugin;
        loadConfig();
    }

    private void loadConfig() {
        if (!plugin.getConfig().contains("discord-sync")) {
            this.moduleEnabled = false;
            return;
        }

        this.moduleEnabled = plugin.getConfig().getBoolean("discord-sync.enabled", false);
        this.unauthorizedAction = plugin.getConfig().getString("discord-sync.unauthorized-action", "shutdown");
        this.verificationTimeoutMs = plugin.getConfig().getLong("discord-sync.verification-timeout-seconds", 300L) * 1000;
        
        this.messageCommandRequiresSync = plugin.getConfig().getString("discord-sync.messages.command-requires-sync", 
            "&cLệnh này yêu cầu xác minh Discord!");
        this.messageVerifyRequired = plugin.getConfig().getString("discord-sync.messages.verify-required", 
            "&eVui lòng xác minh qua Discord trước khi sử dụng lệnh này.");
        this.messageDeop = plugin.getConfig().getString("discord-sync.messages.deop-message", 
            "&cQuyền OP đã bị gỡ do lỗi xác minh bảo mật!");
        this.messageShutdown = plugin.getConfig().getString("discord-sync.messages.shutdown-message", 
            "&cServer đang đóng vì phát hiện nghi vấn bảo mật...");
        this.messageKick = plugin.getConfig().getString("discord-sync.messages.kick-message", 
            "&c[Discord-Sync] Bạn đã bị kick vì cố gắng sử dụng lệnh bảo mật mà chưa xác minh Discord!");
        
        if (!moduleEnabled) {
            return;
        }

        commandRequiresSync.clear();
        List<String> syncCommands = plugin.getConfig().getStringList("discord-sync.commands");

        for (String command : syncCommands) {
            String cleanCmd = command.toLowerCase();
            if (cleanCmd.startsWith("/")) {
                cleanCmd = cleanCmd.substring(1);
            }
            commandRequiresSync.add(cleanCmd);
        }

        plugin.getLogger().info("§a[Discord-Sync] Module enabled for " + commandRequiresSync.size() + " commands: " + commandRequiresSync);
    }

    public boolean commandRequiresSync(String command) {
        if (!moduleEnabled) return false;
        
        String lowerCmd = command.toLowerCase().trim();
        
        if (lowerCmd.startsWith("/")) {
            lowerCmd = lowerCmd.substring(1);
        }
        
        int spaceIndex = lowerCmd.indexOf(' ');
        if (spaceIndex > 0) {
            lowerCmd = lowerCmd.substring(0, spaceIndex);
        }
        
        if (commandRequiresSync.contains(lowerCmd)) {
            return true;
        }
        
        if (lowerCmd.contains(":")) {
            String[] parts = lowerCmd.split(":", 2);
            if (parts.length > 1) {
                String baseCommand = parts[1];
                return commandRequiresSync.contains(baseCommand);
            }
        }
        
        return false;
    }

    public boolean isPlayerVerified(Player player) {
        if (!moduleEnabled) return true;
        
        UUID playerUUID = player.getUniqueId();
        Long verificationTime = playerVerificationTime.get(playerUUID);
        
        if (verificationTime == null) {
            return false;
        }
        
        long now = System.currentTimeMillis();
        if ((now - verificationTime) > verificationTimeoutMs) {
            playerVerificationTime.remove(playerUUID);
            return false;
        }
        
        return true;
    }

    public void verifyPlayer(Player player) {
        if (!moduleEnabled) return;
        
        UUID playerUUID = player.getUniqueId();
        playerVerificationTime.put(playerUUID, System.currentTimeMillis());
        
        plugin.getLogger().info("§a[Discord-Sync] Player " + player.getName() + " verified successfully");
        
        if (plugin.getConfig().getBoolean("discord-sync.log-to-console", true)) {
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (player.isOnline()) {
                    player.sendMessage(ChatColor.translateAlternateColorCodes('&', 
                        "&a✓ Discord xác minh thành công! Bạn có &e" + (verificationTimeoutMs / 1000 / 60) + " phút &ađể sử dụng các lệnh bảo mật."));
                }
            });
        }
    }

    public void unverifyPlayer(Player player) {
        playerVerificationTime.remove(player.getUniqueId());
    }

    public void handleUnauthorizedCommand(Player player, String command) {
        plugin.getLogger().warning("§c[Discord-Sync] ⚠️ UNAUTHORIZED COMMAND: " + player.getName() + " tried /" + command + " (not verified on Discord)");
        
        if (plugin.isDiscordEnabled()) {
            try {
                plugin.getDiscord().sendEmbed("discord-sync-alert", Map.of(
                    "player", player.getName(),
                    "command", command,
                    "action", unauthorizedAction.toUpperCase()
                ), false);
            } catch (Exception e) {
                plugin.getLogger().warning("Could not send Discord alert: " + e.getMessage());
            }
        }

        player.sendMessage(ChatColor.translateAlternateColorCodes('&', messageCommandRequiresSync));
        player.sendMessage(ChatColor.translateAlternateColorCodes('&', messageVerifyRequired));

        switch (unauthorizedAction.toLowerCase()) {
            case "shutdown":
            case "stop":
                player.sendMessage(ChatColor.translateAlternateColorCodes('&', messageShutdown));
                plugin.getLogger().severe("§c[Discord-Sync] SHUTTING DOWN SERVER! Unauthorized: " + player.getName() + " used /" + command);
                
                Bukkit.getScheduler().scheduleSyncDelayedTask(plugin, () -> {
                    plugin.getServer().shutdown();
                }, 40L);
                break;

            case "deop":
                if (player.isOp()) {
                    player.setOp(false);
                    player.sendMessage(ChatColor.translateAlternateColorCodes('&', messageDeop));
                }
                break;

            case "kick":
            default:
                player.kickPlayer(ChatColor.translateAlternateColorCodes('&', messageKick));
                break;
        }
    }

    public long getRemainingVerificationTime(Player player) {
        if (!moduleEnabled) return -1;
        
        UUID playerUUID = player.getUniqueId();
        Long verificationTime = playerVerificationTime.get(playerUUID);
        
        if (verificationTime == null) {
            return 0;
        }
        
        long elapsed = System.currentTimeMillis() - verificationTime;
        long remaining = verificationTimeoutMs - elapsed;
        
        return Math.max(0, remaining / 1000);
    }

    public long getVerificationTimeoutSeconds() {
        return verificationTimeoutMs / 1000;
    }

    public boolean isEnabled() {
        return moduleEnabled;
    }

    public Set<String> getProtectedCommands() {
        return new HashSet<>(commandRequiresSync);
    }

    public void reload() {
        this.commandRequiresSync.clear();
        this.playerVerificationTime.clear();
        loadConfig();
    }

    public void sendVerificationRequest(org.bukkit.entity.Player player) {
        if (!moduleEnabled || !plugin.isDiscordEnabled()) {
            plugin.getLogger().warning("Discord-Sync or Discord not enabled");
            return;
        }

        try {
            String playerIp = player.getAddress() != null ? player.getAddress().getHostString() : "Unknown";
            String verificationCode = String.format("%04d", (player.getUniqueId().hashCode() & 0xFFFF) % 10000);
            String timestamp = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
            String timeoutMinutes = String.valueOf(verificationTimeoutMs / 1000 / 60);
            
            plugin.getDiscord().sendEmbed("discord-sync-request", Map.of(
                "player", player.getName(),
                "uuid", player.getUniqueId().toString(),
                "ip", playerIp,
                "timestamp", timestamp,
                "code", verificationCode,
                "timeout", timeoutMinutes
            ), false);
            
            plugin.getLogger().info("§e[Discord-Sync] Sent verification request for " + player.getName() + " (code: " + verificationCode + ")");
        } catch (Exception e) {
            plugin.getLogger().severe("Failed to send verification request: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

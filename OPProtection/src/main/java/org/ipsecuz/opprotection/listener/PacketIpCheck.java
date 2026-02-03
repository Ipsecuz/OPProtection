package org.ipsecuz.opprotection.listener;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.bukkit.ChatColor;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerLoginEvent;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.utils.GeoIPChecker;

public class PacketIpCheck implements Listener {
    private final OPProtection plugin;
    private final boolean ipForwardingEnabled;
    private final GeoIPChecker geoIPChecker;
    private final File uuidPlayersFile;
    private final File uuidLogFile;

    public PacketIpCheck(OPProtection plugin, boolean ipForwardingEnabled) {
        this.plugin = plugin;
        this.ipForwardingEnabled = ipForwardingEnabled;
        this.geoIPChecker = new GeoIPChecker(plugin);

        File uuidFolder = new File(plugin.getDataFolder(), "uuid");
        if (!uuidFolder.exists()) {
            uuidFolder.mkdirs();
        }
        this.uuidPlayersFile = new File(uuidFolder, "players.yml");
        this.uuidLogFile = new File(uuidFolder, "log.yml");

        try {
            if (!this.uuidPlayersFile.exists()) {
                this.uuidPlayersFile.createNewFile();
            }
            if (!this.uuidLogFile.exists()) {
                this.uuidLogFile.createNewFile();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @EventHandler
    public void onAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        String ip = event.getAddress().getHostAddress();
        if (ip.equals("127.0.0.1") || ip.equals("::1") || ip.startsWith("192.168.") || ip.startsWith("10.")) {
            return;
        }

        if (!this.geoIPChecker.isCountryAllowed(ip)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    ChatColor.translateAlternateColorCodes('&',
                            this.plugin.getConfig().getString("geoip.block-message", "&cQuốc gia của bạn không được phép!"))
            );
        }
    }

    @EventHandler
    public void onPlayerLogin(PlayerLoginEvent event) {
        if (event.getResult() != PlayerLoginEvent.Result.ALLOWED) {
            return;
        }

        String playerName = event.getPlayer().getName();
        String uuid = event.getPlayer().getUniqueId().toString();

        String ip = event.getAddress().getHostAddress();
        if (this.ipForwardingEnabled && event.getRealAddress() != null) {
            ip = event.getRealAddress().getHostAddress();
        }

        final String finalIp = ip;

        this.plugin.getAsyncExecutor().submit(() -> {
            try {
                YamlConfiguration yml = YamlConfiguration.loadConfiguration(this.uuidPlayersFile);
                String path = "players." + playerName;
                long now = System.currentTimeMillis();

                if (!yml.contains(path)) {
                    yml.set(path + ".uuid", uuid);
                    yml.set(path + ".ip", finalIp);
                    yml.set(path + ".firstJoin", now);
                    yml.set(path + ".lastJoin", now);
                    yml.save(this.uuidPlayersFile);
                    this.addLog("NEW_USER", playerName, uuid, finalIp, "First join");
                    return;
                }

                String storedUuid = yml.getString(path + ".uuid");
                if (storedUuid != null && !storedUuid.equalsIgnoreCase(uuid)) {
                    this.addLog("UUID_MISMATCH", playerName, uuid, finalIp, "UUID không khớp (expected " + storedUuid + ")");
                    if (this.plugin.isDiscordEnabled()) {
                        this.plugin.getDiscord().sendSpoofAlertEmbed(playerName, finalIp, "Unknown", storedUuid, "UUID Spoof Detected");
                    }
                    String kickReason = ChatColor.translateAlternateColorCodes('&',
                                    "&eUUID của bạn không khớp với dữ liệu hệ thống!\n" +
                                    "&eVui lòng liên hệ Admin qua Discord ngay lập tức."
                    );
                    event.disallow(PlayerLoginEvent.Result.KICK_OTHER, kickReason);

                    return;
                }

                yml.set(path + ".lastJoin", now);
                yml.set(path + ".ip", finalIp);
                yml.save(this.uuidPlayersFile);
                this.addLog("JOIN", playerName, uuid, finalIp, "Đăng nhập lại");

            } catch (IOException e) {
                this.plugin.getLogger().warning("Failed to save UUID data: " + e.getMessage());
            }
        });
    }

    private void addLog(String type, String player, String uuid, String ip, String detail) {
        try {
            YamlConfiguration logYml = YamlConfiguration.loadConfiguration(this.uuidLogFile);
            List<String> logs = logYml.getStringList("logs");
            String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

            logs.add("[" + time + "] [" + type + "] Player=" + player + " | UUID=" + uuid + " | IP=" + ip + " | Detail=" + detail);

            logYml.set("logs", logs);
            logYml.save(this.uuidLogFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
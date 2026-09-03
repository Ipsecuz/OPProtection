package org.ipsecuz.opprotection.storage;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.ipsecuz.opprotection.OPProtection;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/** Stores mutable security state outside config.yml and writes immutable snapshots asynchronously. */
public final class SecurityDataStore {
    private final OPProtection plugin;
    private final File file;
    private final Object lock = new Object();
    private final Object writeLock = new Object();
    private final AtomicBoolean saveScheduled = new AtomicBoolean(false);
    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private YamlConfiguration data;

    public SecurityDataStore(OPProtection plugin) {
        this.plugin = plugin;
        this.file = new File(plugin.getDataFolder(), "security-data.yml");
        this.data = YamlConfiguration.loadConfiguration(file);
        migrateLegacyUuidRegistry();
    }

    public boolean migrateLegacyConfig(FileConfiguration config) {
        boolean migrated = false;
        synchronized (lock) {
            ConfigurationSection legacyData = config.getConfigurationSection("data");
            if (legacyData != null) {
                for (String uuidText : legacyData.getKeys(false)) {
                    try {
                        UUID uuid = UUID.fromString(uuidText);
                        String password = config.getString("data." + uuidText + ".password");
                        String ip = config.getString("data." + uuidText + ".ip");
                        if (password != null && !password.isBlank() && getPersonalPasswordLocked(uuid) == null) {
                            data.set("players." + uuid + ".password", password);
                            migrated = true;
                        }
                        if (ip != null && !ip.isBlank() && getTrustedIpLocked(uuid) == null) {
                            data.set("players." + uuid + ".trusted-ip", ip);
                            migrated = true;
                        }
                    } catch (IllegalArgumentException ignored) {
                        plugin.getLogger().warning("[Storage] Ignored invalid legacy UUID: " + uuidText);
                    }
                }
                config.set("data", null);
                migrated = true;
            }

            ConfigurationSection legacyIps = config.getConfigurationSection("player-ips");
            if (legacyIps != null) {
                for (String playerName : legacyIps.getKeys(false)) {
                    String ip = legacyIps.getString(playerName);
                    if (ip != null && !ip.isBlank()) {
                        data.set("legacy-name-ips." + playerName.toLowerCase(Locale.ROOT), ip);
                        migrated = true;
                    }
                }
                config.set("player-ips", null);
                migrated = true;
            }
        }
        if (migrated) {
            requestSave();
        }
        return migrated;
    }

    public String getPersonalPassword(UUID uuid) {
        synchronized (lock) {
            return getPersonalPasswordLocked(uuid);
        }
    }

    public void setPersonalPassword(UUID uuid, String hash) {
        synchronized (lock) {
            data.set("players." + uuid + ".password", hash);
        }
        requestSave();
    }

    public String getTrustedIp(UUID uuid) {
        synchronized (lock) {
            return getTrustedIpLocked(uuid);
        }
    }

    public void setTrustedIp(UUID uuid, String ip) {
        synchronized (lock) {
            data.set("players." + uuid + ".trusted-ip", ip);
        }
        requestSave();
    }

    public boolean resetTrustedIp(UUID uuid) {
        boolean existed;
        synchronized (lock) {
            String path = "players." + uuid + ".trusted-ip";
            existed = data.contains(path);
            data.set(path, null);
        }
        if (existed) {
            requestSave();
        }
        return existed;
    }

    public void claimLegacyTrustedIp(String playerName, UUID uuid) {
        if (playerName == null || uuid == null) return;
        boolean changed = false;
        synchronized (lock) {
            String legacyPath = "legacy-name-ips." + playerName.toLowerCase(Locale.ROOT);
            String legacy = data.getString(legacyPath);
            if (legacy != null && !legacy.isBlank() && getTrustedIpLocked(uuid) == null) {
                data.set("players." + uuid + ".trusted-ip", legacy);
                data.set(legacyPath, null);
                changed = true;
            }
        }
        if (changed) requestSave();
    }

    public IdentityCheck recordIdentity(String playerName, UUID joinedUuid, String ip) {
        String key = playerName.toLowerCase(Locale.ROOT);
        long now = System.currentTimeMillis();
        synchronized (lock) {
            String path = "identities." + key;
            String stored = data.getString(path + ".uuid");
            if (stored == null || stored.isBlank()) {
                data.set(path + ".name", playerName);
                data.set(path + ".uuid", joinedUuid.toString());
                data.set(path + ".first-join", now);
                data.set(path + ".last-join", now);
                data.set(path + ".last-ip", ip);
                requestSave();
                return new IdentityCheck(IdentityStatus.NEW, null);
            }
            if (!stored.equalsIgnoreCase(joinedUuid.toString())) {
                return new IdentityCheck(IdentityStatus.MISMATCH, stored);
            }
            data.set(path + ".name", playerName);
            data.set(path + ".last-join", now);
            data.set(path + ".last-ip", ip);
            requestSave();
            return new IdentityCheck(IdentityStatus.MATCH, stored);
        }
    }

    private void migrateLegacyUuidRegistry() {
        File legacy = new File(new File(plugin.getDataFolder(), "uuid"), "players.yml");
        if (!legacy.isFile()) return;
        YamlConfiguration yaml = YamlConfiguration.loadConfiguration(legacy);
        ConfigurationSection players = yaml.getConfigurationSection("players");
        if (players == null) return;
        int migrated = 0;
        synchronized (lock) {
            for (String playerName : players.getKeys(false)) {
                String oldPath = "players." + playerName;
                String uuid = yaml.getString(oldPath + ".uuid");
                if (uuid == null || uuid.isBlank()) continue;
                try {
                    UUID.fromString(uuid);
                } catch (IllegalArgumentException ignored) {
                    plugin.getLogger().warning("[Storage] Bỏ qua UUID legacy không hợp lệ của " + playerName + ": " + uuid);
                    continue;
                }
                String path = "identities." + playerName.toLowerCase(Locale.ROOT);
                if (data.getString(path + ".uuid") != null) continue;
                data.set(path + ".name", playerName);
                data.set(path + ".uuid", uuid);
                data.set(path + ".first-join", yaml.getLong(oldPath + ".firstJoin", System.currentTimeMillis()));
                data.set(path + ".last-join", yaml.getLong(oldPath + ".lastJoin", System.currentTimeMillis()));
                String oldIp = yaml.getString(oldPath + ".realIp", yaml.getString(oldPath + ".ip"));
                if (oldIp != null && !oldIp.isBlank()) data.set(path + ".last-ip", oldIp);
                migrated++;
            }
        }
        if (migrated > 0) {
            plugin.getLogger().info("[Storage] Đã nhập " + migrated + " hồ sơ UUID từ uuid/players.yml.");
            requestSave();
        }
    }

    public void requestSave() {
        dirty.set(true);
        if (!saveScheduled.compareAndSet(false, true)) return;
        plugin.getSchedulerService().runAsyncDelayed(this::drainWrites, 1L, java.util.concurrent.TimeUnit.SECONDS);
    }

    private void drainWrites() {
        try {
            do {
                dirty.set(false);
                writeSnapshot();
            } while (dirty.get());
        } finally {
            saveScheduled.set(false);
            if (dirty.get()) requestSave();
        }
    }

    public void flushBlocking() {
        try {
            dirty.set(false);
            writeSnapshot();
        } catch (Exception exception) {
            plugin.getLogger().severe("[Storage] Could not flush security-data.yml: " + exception.getMessage());
        }
    }

    private void writeSnapshot() {
        String snapshot;
        synchronized (lock) {
            snapshot = data.saveToString();
        }
        synchronized (writeLock) {
            File parent = file.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                plugin.getLogger().warning("[Storage] Could not create data directory.");
            }
            File temporary = new File(file.getParentFile(), file.getName() + ".tmp");
            try {
                Files.writeString(temporary.toPath(), snapshot, StandardCharsets.UTF_8);
                try {
                    Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (IOException atomicUnsupported) {
                    Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
                try {
                    Files.setPosixFilePermissions(file.toPath(),
                            java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
                } catch (UnsupportedOperationException | IOException ignored) {
                    // Windows and some file systems do not support POSIX permissions.
                }
            } catch (IOException exception) {
                plugin.getLogger().severe("[Storage] Could not save security-data.yml: " + exception.getMessage());
            }
        }
    }

    private String getPersonalPasswordLocked(UUID uuid) {
        return data.getString("players." + uuid + ".password");
    }

    private String getTrustedIpLocked(UUID uuid) {
        return data.getString("players." + uuid + ".trusted-ip");
    }

    public enum IdentityStatus {
        NEW,
        MATCH,
        MISMATCH
    }

    public record IdentityCheck(IdentityStatus status, String expectedUuid) {
    }
}

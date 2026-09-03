package org.ipsecuz.opprotection.security;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.ipsecuz.opprotection.OPProtection;

import java.io.File;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Registry for premium accounts verified by admin (Tier B).
 *
 * <p>On cracked servers (online-mode=false, ip-forwarding=false), this registry
 * allows administrators to mark player names as premium-verified so those players
 * can skip the 2FA step when {@code premium-auth.op-whitelist-premium-auto-bypass-2fa}
 * is enabled. This is safe ONLY when an admin has manually verified ownership of the
 * premium account.</p>
 *
 * <p>Entries are ONLY added or removed from the console by an admin. The old
 * automatic {@code AUTO_LOOKUP} self-registration path was removed: name-based
 * Mojang detection is now a transient PRE state handled by
 * {@link PremiumAccountChecker} and is never persisted here.</p>
 */
public final class PremiumRegistry {
    private final OPProtection plugin;
    private final File file;
    private final Object ioLock = new Object();
    private final AtomicBoolean saveScheduled = new AtomicBoolean();
    private volatile boolean dirty;
    private volatile YamlConfiguration data;
    private final ConcurrentMap<String, Entry> registry = new ConcurrentHashMap<>();

    public PremiumRegistry(OPProtection plugin) {
        this.plugin = plugin;
        this.file = new File(plugin.getDataFolder(), "premium-registry.yml");
        this.data = YamlConfiguration.loadConfiguration(file);
        loadFromDisk();
    }

    /**
     * Register a player name as premium-verified.
     *
     * @param playerName the Minecraft username
     * @param verifiedBy who verified (admin name or "AUTO")
     * @param method verification method: "ADMIN", "DISCORD"
     */
    public void register(String playerName, String verifiedBy, String method) {
        if (playerName == null || playerName.isBlank()) return;
        String key = playerName.toLowerCase(Locale.ROOT);
        long now = System.currentTimeMillis();
        Entry entry = new Entry(playerName, verifiedBy == null ? "UNKNOWN" : verifiedBy,
                method == null ? "ADMIN" : method, now);
        registry.put(key, entry);
        synchronized (ioLock) {
            data.set("entries." + key + ".name", entry.name());
            data.set("entries." + key + ".verified-by", entry.verifiedBy());
            data.set("entries." + key + ".method", entry.method());
            data.set("entries." + key + ".verified-at", entry.verifiedAt());
        }
        scheduleSave();
    }

    /**
     * Remove a player name from the premium registry.
     */
    public boolean unregister(String playerName) {
        if (playerName == null) return false;
        String key = playerName.toLowerCase(Locale.ROOT);
        Entry removed = registry.remove(key);
        if (removed != null) {
            synchronized (ioLock) {
                data.set("entries." + key, null);
            }
            scheduleSave();
            return true;
        }
        return false;
    }

    /**
     * Check if a player name is registered as premium-verified.
     */
    public boolean isPremiumVerified(String playerName) {
        if (playerName == null) return false;
        String key = playerName.toLowerCase(Locale.ROOT);
        return registry.containsKey(key);
    }

    /**
     * Get the entry for a registered premium player.
     */
    public Entry getEntry(String playerName) {
        if (playerName == null) return null;
        String key = playerName.toLowerCase(Locale.ROOT);
        return registry.get(key);
    }

    /**
     * Get all registered player names.
     */
    public Set<String> getRegisteredNames() {
        return Set.copyOf(registry.keySet());
    }

    /**
     * Get the total number of registered premium accounts.
     */
    public int size() {
        return registry.size();
    }

    /**
     * Reload registry from disk.
     */
    public void reload() {
        synchronized (ioLock) {
            this.data = YamlConfiguration.loadConfiguration(file);
            loadFromDisk();
        }
    }

    private void loadFromDisk() {
        registry.clear();
        ConfigurationSection section = data.getConfigurationSection("entries");
        if (section == null) return;
        for (String key : section.getKeys(false)) {
            String name = section.getString(key + ".name", key);
            String verifiedBy = section.getString(key + ".verified-by", "UNKNOWN");
            String method = section.getString(key + ".method", "ADMIN");
            long verifiedAt = section.getLong(key + ".verified-at", 0L);
            registry.put(key, new Entry(name, verifiedBy, method, verifiedAt));
        }
        plugin.getLogger().info("[PremiumRegistry] Đã tải " + registry.size() + " tài khoản premium đã xác minh.");
    }

    /**
     * Asynchronously persist the registry. Disk IO never runs on the calling thread:
     * registrations happen on console/region threads where a blocking save would stall
     * ticks, especially on Folia.
     */
    private void scheduleSave() {
        dirty = true;
        if (!saveScheduled.compareAndSet(false, true)) return;
        plugin.getSchedulerService().runAsyncDelayed(() -> {
            try {
                do {
                    dirty = false;
                    writeDisk();
                } while (dirty);
            } finally {
                saveScheduled.set(false);
                if (dirty) scheduleSave();
            }
        }, 500L, TimeUnit.MILLISECONDS);
    }

    /** Force-write pending changes synchronously; called during plugin shutdown only. */
    public void flushBlocking() {
        if (!dirty) return;
        dirty = false;
        writeDisk();
    }

    private void writeDisk() {
        synchronized (ioLock) {
            try {
                data.save(file);
            } catch (Exception ex) {
                plugin.getLogger().warning("[PremiumRegistry] Không thể lưu premium-registry.yml: " + ex.getMessage());
            }
        }
    }

    public record Entry(String name, String verifiedBy, String method, long verifiedAt) { }
}

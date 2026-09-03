package org.ipsecuz.opprotection.utils;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.ipsecuz.opprotection.OPProtection;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

/**
 * Loads modular config files from the {@code config/} directory and merges them
 * into the main plugin configuration. Module files take precedence over values
 * defined in the root {@code config.yml}.
 *
 * <p>Module files are YAML files inside {@code plugins/OPProtection/config/}.
 * Each module's top-level key is preserved, so {@code config/premium.yml}
 * containing {@code premium-auth:} merges identically to having that section
 * in the root config.</p>
 *
 * <p><b>Important</b>: The root {@code config.yml} must NOT contain feature
 * settings — only metadata like {@code config-version}. Feature settings live
 * exclusively in {@code config/*.yml}. This prevents two real bugs:
 * <ul>
 *   <li>Module files overwriting root values silently on reload.</li>
 *   <li>{@code plugin.saveConfig()} flushing the merged config back into
 *       {@code config.yml}, polluting it with every module key.</li>
 * </ul>
 * Mutable runtime values that the plugin writes back (e.g. {@code op-password})
 * must be persisted via {@link #saveCoreValue(String, Object)} which writes
 * directly to {@code config/core.yml}.</p>
 */
public final class ConfigCache {
    private static final String CONFIG_DIR = "config";
    private static final String CORE_FILE_NAME = "core.yml";

    private final OPProtection plugin;
    private final Set<String> loadedModules = new LinkedHashSet<>();

    public ConfigCache(OPProtection plugin) {
        this.plugin = plugin;
    }

    /**
     * Reload all module configs and merge them into the main FileConfiguration.
     * Called once at startup and whenever the admin runs {@code /opreload}.
     */
    public void reload() {
        loadedModules.clear();
        File moduleDir = new File(plugin.getDataFolder(), CONFIG_DIR);

        // Ensure the module directory exists and seed default files
        if (!moduleDir.exists()) {
            moduleDir.mkdirs();
            seedDefaults(moduleDir);
        }

        File[] moduleFiles = moduleDir.listFiles((dir, name) ->
                name.endsWith(".yml") || name.endsWith(".yaml"));

        if (moduleFiles == null || moduleFiles.length == 0) {
            plugin.getLogger().info("[Config] Không tìm thấy module config nào trong " + CONFIG_DIR + "/");
            return;
        }

        // Sort for deterministic order
        Arrays.sort(moduleFiles);

        FileConfiguration merged = plugin.getConfig();

        for (File moduleFile : moduleFiles) {
            String moduleName = moduleFile.getName();
            try {
                FileConfiguration moduleConfig = YamlConfiguration.loadConfiguration(moduleFile);
                mergeSection(merged, moduleConfig, "");
                loadedModules.add(moduleName);
            } catch (Exception ex) {
                plugin.getLogger().warning("[Config] Không thể load module '" + moduleName + "': " + ex.getMessage());
            }
        }

        plugin.getLogger().info("[Config] Đã load " + loadedModules.size() + " module: " + String.join(", ", loadedModules));
    }

    /**
     * Merge all keys from {@code source} into {@code target} recursively.
     * Existing keys in target that are NOT in source are preserved.
     * Keys in source overwrite those in target.
     *
     * <p>Lists are merged as ordered unions instead of overwriting, so a module file
     * extends a list defined in the root config rather than replacing it.</p>
     */
    private void mergeSection(FileConfiguration target, ConfigurationSection source, String path) {
        for (String key : source.getKeys(false)) {
            String fullPath = path.isEmpty() ? key : path + "." + key;
            Object value = source.get(key);

            if (value instanceof ConfigurationSection section) {
                // If target doesn't have this section yet, create it
                if (!target.contains(fullPath)) {
                    target.createSection(fullPath);
                }
                mergeSection(target, section, fullPath);
            } else if (value instanceof List<?> incoming && target.get(fullPath) instanceof List<?> current) {
                target.set(fullPath, mergeLists(current, incoming));
            } else {
                target.set(fullPath, value);
            }
        }
    }

    private static List<Object> mergeLists(List<?> current, List<?> incoming) {
        List<Object> merged = new ArrayList<>(current.size() + incoming.size());
        merged.addAll(current);
        for (Object item : incoming) {
            if (item == null) continue;
            if (!merged.contains(item)) merged.add(item);
        }
        return merged;
    }

    /**
     * Seed the config/ directory with default module files from the JAR resources.
     */
    private void seedDefaults(File moduleDir) {
        String[] moduleFiles = {
                "core.yml",
                "commands.yml",
                "security.yml",
                "geoip.yml",
                "domain.yml",
                "discord.yml",
                "discord-sync.yml",
                "premium.yml",
                "brand.yml"
        };
        for (String fileName : moduleFiles) {
            String resourcePath = CONFIG_DIR + "/" + fileName;
            try {
                plugin.saveResource(resourcePath, false);
            } catch (IllegalArgumentException ignored) {
                // Resource not found in JAR — skip silently
            }
        }
    }

    /**
     * Persist a single value into {@code config/core.yml} on disk.
     *
     * <p>Use this for mutable runtime keys that the plugin writes back
     * (e.g. {@code op-password}). This avoids {@code plugin.saveConfig()}
     * which would flush the entire merged config back into {@code config.yml}
     * and re-introduce the duplication/conflict bug.</p>
     *
     * <p>The in-memory {@link org.bukkit.plugin.java.JavaPlugin#getConfig()}
     * is also updated so subsequent reads see the new value without a reload.</p>
     *
     * @param path  dotted path inside core.yml, e.g. {@code "op-password"}
     * @param value new value (String / Number / Boolean / List / null)
     */
    public void saveCoreValue(String path, Object value) {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("path must not be empty");
        }

        // 1) Update the in-memory merged config so reads see the new value immediately.
        plugin.getConfig().set(path, value);

        // 2) Persist directly to config/core.yml on disk.
        File coreFile = new File(new File(plugin.getDataFolder(), CONFIG_DIR), CORE_FILE_NAME);
        if (!coreFile.exists()) {
            // Module dir might have been wiped — re-seed core.yml from JAR defaults.
            try {
                plugin.saveResource(CONFIG_DIR + "/" + CORE_FILE_NAME, false);
            } catch (IllegalArgumentException ignored) {
                // No default resource — fall through and create an empty file below.
            }
        }

        try {
            YamlConfiguration coreConfig = YamlConfiguration.loadConfiguration(coreFile);
            coreConfig.set(path, value);
            coreConfig.save(coreFile);
        } catch (IOException ex) {
            plugin.getLogger().log(Level.SEVERE,
                    "[Config] Không thể lưu '" + path + "' vào " + CONFIG_DIR + "/" + CORE_FILE_NAME + ": " + ex.getMessage(), ex);
        } catch (Exception ex) {
            plugin.getLogger().severe("[Config] Lỗi không xác định khi lưu '" + path + "' vào "
                    + CONFIG_DIR + "/" + CORE_FILE_NAME + ": " + ex.getMessage());
        }
    }

    /**
     * Migrate any root-level keys that should live in {@code config/core.yml} but
     * still linger in the legacy {@code config.yml} (from installs upgraded from
     * an older build that put features in the root file).
     *
     * <p>Currently migrates: {@code op-password}, {@code op-whitelist},
     * {@code metric}, {@code ip-forwarding}.</p>
     *
     * <p>This MUST be called BEFORE {@link #reload()} so that legacy plaintext
     * values in root are not silently overwritten by the module file's default
     * (empty) value during the merge. For {@code op-password}, a legacy plaintext
     * value is automatically hashed via PBKDF2 before being written to
     * {@code config/core.yml}.</p>
     */
    public void migrateLegacyRootKeys() {
        File coreFile = new File(new File(plugin.getDataFolder(), CONFIG_DIR), CORE_FILE_NAME);
        if (!coreFile.exists()) {
            try {
                plugin.saveResource(CONFIG_DIR + "/" + CORE_FILE_NAME, false);
            } catch (IllegalArgumentException ignored) {
                // No default in JAR — create empty file below when saving.
            }
        }

        YamlConfiguration coreConfig = YamlConfiguration.loadConfiguration(coreFile);
        File rootFile = new File(plugin.getDataFolder(), "config.yml");
        YamlConfiguration rootConfig = YamlConfiguration.loadConfiguration(rootFile);

        // Order matters: op-password first because we may need to hash it.
        String[] legacyKeys = {
                "op-password",
                "op-whitelist",
                "metric",
                "ip-forwarding"
        };

        boolean coreDirty = false;
        boolean rootDirty = false;

        for (String key : legacyKeys) {
            if (!rootConfig.contains(key, true)) continue;
            Object rootValue = rootConfig.get(key);
            Object coreValue = coreConfig.get(key);

            // Special handling for op-password: hash any legacy plaintext before persisting.
            if ("op-password".equals(key) && rootValue instanceof String s && !s.isBlank()) {
                if (!org.ipsecuz.opprotection.security.PasswordHasher.isStrongHash(s)) {
                    try {
                        String hash = org.ipsecuz.opprotection.security.PasswordHasher.hash(s);
                        coreConfig.set(key, hash);
                        coreDirty = true;
                        plugin.getLogger().warning("[Config] Đã migrate op-password plaintext cũ sang PBKDF2 hash tại config/" + CORE_FILE_NAME + ".");
                    } catch (Exception ex) {
                        plugin.getLogger().severe("[Config] Không thể hash op-password legacy: " + ex.getMessage());
                        // Preserve the value in core.yml as-is so admin can re-set via /oppass createpass.
                        coreConfig.set(key, s);
                        coreDirty = true;
                    }
                } else {
                    // Already a strong hash — copy to core.yml if core doesn't have one.
                    if (coreValue == null || (coreValue instanceof String cs && cs.isBlank())) {
                        coreConfig.set(key, rootValue);
                        coreDirty = true;
                    }
                }
                rootConfig.set(key, null);
                rootDirty = true;
                continue;
            }

            // Skip migration when the root value equals the core value (just clear the duplicate).
            boolean sameDefault = (rootValue == null && coreValue == null)
                    || (rootValue != null && rootValue.equals(coreValue));
            if (sameDefault) {
                rootConfig.set(key, null);
                rootDirty = true;
                continue;
            }

            // Prefer the root value if core is empty/default and root actually carries user data.
            if (coreValue == null
                    || (coreValue instanceof String s && s.isBlank())
                    || (coreValue instanceof List<?> l && l.isEmpty())) {
                coreConfig.set(key, rootValue);
                coreDirty = true;
            }
            // Always strip the key from root so the conflict cannot reappear.
            rootConfig.set(key, null);
            rootDirty = true;
        }

        try {
            if (coreDirty) {
                coreConfig.save(coreFile);
                plugin.getLogger().info("[Config] Đã migrate một số key legacy từ config.yml sang config/" + CORE_FILE_NAME + ".");
            }
            if (rootDirty) {
                rootConfig.save(rootFile);
                plugin.getLogger().info("[Config] Đã dọn các key trùng khỏi config.yml.");
            }
        } catch (IOException ex) {
            plugin.getLogger().severe("[Config] migrateLegacyRootKeys IO error: " + ex.getMessage());
        }
    }

    public Set<String> getLoadedModules() {
        return java.util.Set.copyOf(loadedModules);
    }
}

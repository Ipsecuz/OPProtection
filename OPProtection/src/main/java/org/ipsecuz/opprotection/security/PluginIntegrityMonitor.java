package org.ipsecuz.opprotection.security;

import org.bukkit.configuration.file.YamlConfiguration;
import org.ipsecuz.opprotection.OPProtection;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Detects persistent changes to plugin JAR files using a local SHA-256 baseline.
 * It warns instead of deleting or disabling files to avoid destructive false positives.
 */
public final class PluginIntegrityMonitor {
    private static final Pattern YAML_PLUGIN_NAME = Pattern.compile(
            "(?im)^\\s*name\\s*:\\s*[\\\"']?([^\\\"'#\\r\\n]+)");
    private static final Pattern JSON_PLUGIN_NAME = Pattern.compile(
            "(?i)\\\"name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final List<String> DESCRIPTOR_FILES = List.of(
            "plugin.yml",
            "paper-plugin.yml",
            "bungee.yml",
            "velocity-plugin.json"
    );

    private final OPProtection plugin;
    private final Path baselineFile;
    private final AtomicBoolean scanRunning = new AtomicBoolean();

    private volatile Map<String, Fingerprint> baseline = Map.of();
    private volatile List<Change> lastChanges = List.of();
    private volatile Object scheduledTask;

    public PluginIntegrityMonitor(OPProtection plugin) {
        this.plugin = plugin;
        this.baselineFile = plugin.getDataFolder().toPath().resolve("plugin-hashes.yml");
    }

    public void start() {
        if (!plugin.getConfig().getBoolean("integrity-check.enabled", true)) return;
        loadBaseline();
        scanAsync(false);
        long minutes = Math.max(5L,
                plugin.getConfig().getLong("integrity-check.interval-minutes", 30L));
        this.scheduledTask = plugin.getSchedulerService().runGlobalAtFixedRate(
                () -> scanAsync(false),
                minutes * 60L * 20L,
                minutes * 60L * 20L
        );
    }

    public void stop() {
        plugin.getSchedulerService().cancel(scheduledTask);
        scheduledTask = null;
    }

    public void scanAsync(boolean announceClean) {
        if (!scanRunning.compareAndSet(false, true)) {
            if (announceClean) plugin.getLogger().warning("Đang có một lượt kiểm tra plugin JAR khác chạy.");
            return;
        }

        plugin.getAsyncExecutor().execute(() -> {
            try {
                Map<String, Fingerprint> current = scanNow();
                if (baseline.isEmpty()) {
                    writeBaseline(current);
                    baseline = Map.copyOf(current);
                    plugin.getLogger().warning("Đã tạo baseline SHA-256 lần đầu cho "
                            + current.size() + " plugin JAR.");
                    plugin.getLogger().warning("Baseline chỉ ghi nhận trạng thái hiện tại; "
                            + "hãy tự kiểm tra nguồn plugin trước khi xem là đáng tin cậy.");
                    return;
                }

                List<Change> changes = compare(baseline, current);
                lastChanges = List.copyOf(changes);
                if (changes.isEmpty()) {
                    if (announceClean) {
                        plugin.getLogger().info("Không phát hiện plugin JAR mới, bị thay đổi hoặc bị xóa.");
                    }
                    return;
                }

                announceChanges(changes);
                for (Change change : changes) {
                    plugin.getAuditLog().write(
                            "PLUGIN_HASH_" + change.type.name(),
                            change.file,
                            "",
                            "",
                            change.detail
                    );
                }
            } catch (Exception ex) {
                plugin.getLogger().severe("Không thể kiểm tra plugin JAR: " + ex.getMessage());
            } finally {
                scanRunning.set(false);
            }
        });
    }

    public void acceptCurrentBaselineAsync(Consumer<Boolean> callback) {
        if (!scanRunning.compareAndSet(false, true)) {
            callback.accept(false);
            return;
        }

        plugin.getAsyncExecutor().execute(() -> {
            boolean success = false;
            try {
                Map<String, Fingerprint> current = scanNow();
                writeBaseline(current);
                baseline = Map.copyOf(current);
                lastChanges = List.of();
                success = true;
                plugin.getLogger().warning("Console đã chấp nhận baseline SHA-256 mới gồm "
                        + current.size() + " plugin JAR.");
                plugin.getLogger().warning("Lưu ý: hashaccept chỉ xác nhận trạng thái file hiện tại, "
                        + "không chứng minh plugin là an toàn.");
                plugin.getAuditLog().write(
                        "PLUGIN_HASH_ACCEPT",
                        "CONSOLE",
                        "",
                        "",
                        "Accepted " + current.size() + " JARs"
                );
            } catch (Exception ex) {
                plugin.getLogger().severe("Không thể cập nhật baseline plugin JAR: " + ex.getMessage());
            } finally {
                scanRunning.set(false);
                boolean result = success;
                plugin.getSchedulerService().runGlobal(() -> callback.accept(result));
            }
        });
    }

    public List<Change> getLastChanges() {
        return lastChanges;
    }

    private void announceChanges(List<Change> changes) {
        Map<ChangeType, LinkedHashSet<String>> grouped = new EnumMap<>(ChangeType.class);
        for (ChangeType type : ChangeType.values()) grouped.put(type, new LinkedHashSet<>());
        for (Change change : changes) grouped.get(change.type).add(change.pluginName);

        plugin.getLogger().severe("============================================================");
        plugin.getLogger().severe("PHÁT HIỆN THAY ĐỔI TRONG THƯ MỤC PLUGINS - CHƯA TỰ ĐỘNG TIN CẬY!");
        logGroup(ChangeType.NEW, grouped.get(ChangeType.NEW));
        logGroup(ChangeType.CHANGED, grouped.get(ChangeType.CHANGED));
        logGroup(ChangeType.REMOVED, grouped.get(ChangeType.REMOVED));
        plugin.getLogger().severe("[NEW] chỉ có nghĩa plugin mới chưa nằm trong baseline, "
                + "không khẳng định plugin đó là mã độc.");
        plugin.getLogger().severe("Nếu chính bạn vừa thêm, cập nhật hoặc xóa plugin hợp lệ, "
                + "hãy kiểm tra nguồn file rồi chạy:");
        plugin.getLogger().severe("/opreload hashaccept");
        plugin.getLogger().severe("Lệnh trên chấp nhận toàn bộ plugin JAR hiện tại làm baseline mới.");
        plugin.getLogger().severe("============================================================");
    }

    private void logGroup(ChangeType type, Set<String> names) {
        if (names == null || names.isEmpty()) return;
        plugin.getLogger().severe("[" + type.name() + "] " + String.join(", ", names));
    }

    private Map<String, Fingerprint> scanNow() throws IOException {
        Path pluginsDirectory = plugin.getDataFolder().toPath().getParent();
        if (pluginsDirectory == null || !Files.isDirectory(pluginsDirectory)) {
            throw new IOException("Không tìm thấy thư mục plugins");
        }

        Map<String, Fingerprint> result = new LinkedHashMap<>();
        try (Stream<Path> stream = Files.list(pluginsDirectory)) {
            List<Path> jars = stream
                    .filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString().toLowerCase(Locale.ROOT)))
                    .toList();

            for (Path jar : jars) {
                String fileName = jar.getFileName().toString();
                String pluginName = readPluginName(jar, fileName);
                result.put(fileName, new Fingerprint(
                        sha256(jar),
                        Files.size(jar),
                        Files.getLastModifiedTime(jar).toMillis(),
                        pluginName
                ));
            }
        }
        return result;
    }

    private List<Change> compare(Map<String, Fingerprint> expected, Map<String, Fingerprint> current) {
        List<Change> changes = new ArrayList<>();

        for (Map.Entry<String, Fingerprint> entry : current.entrySet()) {
            Fingerprint old = expected.get(entry.getKey());
            Fingerprint now = entry.getValue();
            if (old == null) {
                changes.add(new Change(
                        ChangeType.NEW,
                        entry.getKey(),
                        now.pluginName,
                        "sha256=" + now.sha256
                ));
            } else if (!MessageDigest.isEqual(hexBytes(old.sha256), hexBytes(now.sha256))) {
                changes.add(new Change(
                        ChangeType.CHANGED,
                        entry.getKey(),
                        now.pluginName,
                        "old=" + old.sha256 + ", new=" + now.sha256
                ));
            }
        }

        for (Map.Entry<String, Fingerprint> entry : expected.entrySet()) {
            if (!current.containsKey(entry.getKey())) {
                Fingerprint old = entry.getValue();
                changes.add(new Change(
                        ChangeType.REMOVED,
                        entry.getKey(),
                        old.pluginName,
                        "old=" + old.sha256
                ));
            }
        }

        changes.sort(Comparator
                .comparing((Change change) -> change.type.ordinal())
                .thenComparing(change -> change.pluginName.toLowerCase(Locale.ROOT)));
        return changes;
    }

    private void loadBaseline() {
        if (!Files.exists(baselineFile)) {
            baseline = Map.of();
            return;
        }

        YamlConfiguration yaml = YamlConfiguration.loadConfiguration(baselineFile.toFile());
        Map<String, Fingerprint> loaded = new LinkedHashMap<>();
        if (yaml.getConfigurationSection("plugins") != null) {
            for (String key : yaml.getConfigurationSection("plugins").getKeys(false)) {
                String path = "plugins." + key;
                String file = yaml.getString(path + ".file");
                String hash = yaml.getString(path + ".sha256");
                if (file == null || hash == null || !hash.matches("[0-9a-fA-F]{64}")) continue;

                String pluginName = sanitizePluginName(
                        yaml.getString(path + ".name"),
                        file
                );
                loaded.put(file, new Fingerprint(
                        hash.toLowerCase(Locale.ROOT),
                        yaml.getLong(path + ".size"),
                        yaml.getLong(path + ".modified"),
                        pluginName
                ));
            }
        }
        baseline = Map.copyOf(loaded);
    }

    private void writeBaseline(Map<String, Fingerprint> values) throws IOException {
        YamlConfiguration yaml = new YamlConfiguration();
        yaml.set("format", 2);
        yaml.set("accepted-at", Instant.now().toString());

        int index = 0;
        for (Map.Entry<String, Fingerprint> entry : values.entrySet()) {
            String path = "plugins.p" + index++;
            Fingerprint fingerprint = entry.getValue();
            yaml.set(path + ".file", entry.getKey());
            yaml.set(path + ".name", fingerprint.pluginName);
            yaml.set(path + ".sha256", fingerprint.sha256);
            yaml.set(path + ".size", fingerprint.size);
            yaml.set(path + ".modified", fingerprint.modified);
        }

        Files.createDirectories(baselineFile.getParent());
        Path temporary = baselineFile.resolveSibling(baselineFile.getFileName() + ".tmp");
        yaml.save(temporary.toFile());
        try {
            Files.move(
                    temporary,
                    baselineFile,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
            );
        } catch (IOException ex) {
            Files.move(temporary, baselineFile, StandardCopyOption.REPLACE_EXISTING);
        }

        try {
            Files.setPosixFilePermissions(
                    baselineFile,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")
            );
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows and some file systems do not support POSIX permissions.
        }
    }

    private static String readPluginName(Path jar, String fileName) {
        try (JarFile jarFile = new JarFile(jar.toFile(), false)) {
            for (String descriptor : DESCRIPTOR_FILES) {
                JarEntry entry = jarFile.getJarEntry(descriptor);
                if (entry == null || entry.isDirectory()) continue;

                try (InputStream input = jarFile.getInputStream(entry)) {
                    String content = new String(input.readNBytes(128 * 1024), StandardCharsets.UTF_8);
                    Matcher matcher = descriptor.endsWith(".json")
                            ? JSON_PLUGIN_NAME.matcher(content)
                            : YAML_PLUGIN_NAME.matcher(content);
                    if (matcher.find()) return sanitizePluginName(matcher.group(1), fileName);
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // Fall back to a readable name derived from the file name.
        }
        return sanitizePluginName(null, fileName);
    }

    private static String sanitizePluginName(String configuredName, String fileName) {
        String value = configuredName == null ? "" : configuredName.trim();
        value = value.replaceAll("(?i)§[0-9A-FK-ORX]", "")
                .replace(',', '_')
                .replace('|', '_')
                .trim();
        if (!value.isBlank()) return value;

        String fallback = fileName == null ? "UnknownPlugin" : fileName;
        if (fallback.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            fallback = fallback.substring(0, fallback.length() - 4);
        }
        fallback = fallback.replaceFirst("-(?:v)?\\d+(?:[._-].*)?$", "");
        return fallback.isBlank() ? "UnknownPlugin" : fallback;
    }

    private static String sha256(Path file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(file)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) digest.update(buffer, 0, read);
                }
            }
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("JVM không hỗ trợ SHA-256", impossible);
        }
    }

    private static byte[] hexBytes(String hex) {
        try {
            return java.util.HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException ignored) {
            return new byte[0];
        }
    }

    public enum ChangeType { NEW, CHANGED, REMOVED }

    private record Fingerprint(String sha256, long size, long modified, String pluginName) { }

    public record Change(ChangeType type, String file, String pluginName, String detail) { }
}

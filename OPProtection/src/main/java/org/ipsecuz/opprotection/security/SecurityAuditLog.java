package org.ipsecuz.opprotection.security;

import org.ipsecuz.opprotection.OPProtection;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.concurrent.Executor;

/** Append-only, serialized and size-bounded security audit log. */
public final class SecurityAuditLog {
    private final OPProtection plugin;
    private final Executor executor;
    private final Path file;
    private final Object writeLock = new Object();
    private volatile long maxBytes;
    private volatile int retainedFiles;

    public SecurityAuditLog(OPProtection plugin, Executor executor) {
        this.plugin = plugin;
        this.executor = executor;
        this.file = plugin.getDataFolder().toPath().resolve("security-audit.log");
        reload();
    }

    public void reload() {
        this.maxBytes = Math.max(1L, plugin.getConfig().getLong("audit-log.max-size-mb", 20L)) * 1024L * 1024L;
        this.retainedFiles = Math.max(1, Math.min(20, plugin.getConfig().getInt("audit-log.retained-files", 5)));
    }

    public void write(String type, String player, String uuid, String ip, String detail) {
        String line = "%s [%s] player=%s uuid=%s ip=%s detail=%s%n".formatted(
                Instant.now(), clean(type), clean(player), clean(uuid), clean(ip), clean(detail));
        executor.execute(() -> append(line));
    }

    private void append(String line) {
        synchronized (writeLock) {
            try {
                Files.createDirectories(file.getParent());
                rotateIfNeeded(line.getBytes(StandardCharsets.UTF_8).length);
                try (BufferedWriter writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
                    writer.write(line);
                }
                securePermissions(file);
            } catch (IOException ex) {
                plugin.getLogger().warning("[AuditLog] Không thể ghi log: " + ex.getMessage());
            }
        }
    }

    private void rotateIfNeeded(int incomingBytes) throws IOException {
        long configuredMaxBytes = maxBytes;
        if (!Files.exists(file) || Files.size(file) + incomingBytes <= configuredMaxBytes) return;
        int retained = retainedFiles;
        Files.deleteIfExists(file.resolveSibling(file.getFileName() + "." + retained));
        for (int index = retained - 1; index >= 1; index--) {
            Path source = file.resolveSibling(file.getFileName() + "." + index);
            if (Files.exists(source)) {
                Files.move(source, file.resolveSibling(file.getFileName() + "." + (index + 1)),
                        StandardCopyOption.REPLACE_EXISTING);
            }
        }
        Files.move(file, file.resolveSibling(file.getFileName() + ".1"), StandardCopyOption.REPLACE_EXISTING);
    }

    private static void securePermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows and some file systems do not support POSIX permissions.
        }
    }

    private static String clean(String input) {
        return input == null ? "" : input.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
    }
}

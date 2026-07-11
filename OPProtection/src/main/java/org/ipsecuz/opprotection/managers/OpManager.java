package org.ipsecuz.opprotection.managers;

import io.papermc.paper.event.player.AsyncChatEvent;
import net.md_5.bungee.api.ChatMessageType;
import net.md_5.bungee.api.chat.TextComponent;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.GameMode;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.server.ServerCommandEvent;
import org.bukkit.permissions.PermissionAttachment;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.util.Vector;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.integration.luckperms.LuckPermsHook;
import org.ipsecuz.opprotection.integration.luckperms.LuckPermsHookFactory;
import org.ipsecuz.opprotection.security.AttemptLimiter;
import org.ipsecuz.opprotection.security.PasswordHasher;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/** Central privilege state machine. All OP and LuckPerms-* grants pass through this class. */
public final class OpManager implements Listener {
    private final OPProtection plugin;
    private final SecureRandom secureRandom = new SecureRandom();
    private final AttemptLimiter passwordLimiter;
    private final AttemptLimiter twoFactorLimiter;
    private final LuckPermsHook luckPermsHook;

    private volatile Set<String> opWhitelist = Set.of();
    private volatile String opPassword = "";
    private volatile int passTimeout = 60;
    private volatile Set<String> disabledCommandsRaw = Set.of();
    private volatile List<String> logoutActions = List.of();
    private volatile boolean antiSpamEnabled;
    private volatile long antiSpamDelayMillis;
    private volatile String antiSpamMessage = "&cHãy chậm lại.";
    private volatile long verificationResetTicks;
    private volatile boolean discordTwoFactorEnabled;
    private volatile long twoFactorTimeoutMillis;
    private volatile int generatedPasswordLength;
    private volatile int passwordMinLength;
    private volatile String verificationTimeoutAction = "ban";
    private volatile Set<String> allowedCommands = Set.of();

    private final Set<UUID> confirmed = ConcurrentHashMap.newKeySet();
    private final Set<UUID> locked = ConcurrentHashMap.newKeySet();
    private final Set<UUID> awaitingConsole = ConcurrentHashMap.newKeySet();
    private final Set<UUID> passwordChecksInFlight = ConcurrentHashMap.newKeySet();
    private final Set<UUID> twoFAReady = ConcurrentHashMap.newKeySet();
    private final Set<UUID> authorizedStarGrant = ConcurrentHashMap.newKeySet();
    private final Map<UUID, VerificationMethod> verificationMethods = new ConcurrentHashMap<>();
    private final Map<UUID, String> twoFactorCodes = new ConcurrentHashMap<>();
    private final Map<UUID, Long> twoFactorExpiry = new ConcurrentHashMap<>();
    private final Map<Long, UUID> discordToPlayer = new ConcurrentHashMap<>();
    private final Map<UUID, PermissionAttachment> temporaryPermissions = new ConcurrentHashMap<>();
    private final Map<UUID, PlayerSnapshot> snapshots = new ConcurrentHashMap<>();
    private final Map<UUID, PendingGrant> pendingGrants = new ConcurrentHashMap<>();
    private final Map<UUID, Object> countdownTasks = new ConcurrentHashMap<>();
    private final Map<UUID, Object> sessionResetTasks = new ConcurrentHashMap<>();
    private final Map<UUID, Object> sessionWarningTasks = new ConcurrentHashMap<>();
    private final Map<UUID, Long> commandTimestamps = new ConcurrentHashMap<>();
    private final Map<UUID, AtomicLong> generations = new ConcurrentHashMap<>();

    public OpManager(OPProtection plugin, Set<String> opWhitelist, String opPassword, int passTimeout,
                     Set<String> disabledCommandsRaw, List<String> logoutActions) {
        this.plugin = plugin;
        this.passwordLimiter = new AttemptLimiter(5, 60, 120);
        this.twoFactorLimiter = new AttemptLimiter(5, 60, 180);
        reload(opWhitelist, opPassword, passTimeout, disabledCommandsRaw, logoutActions);
        Bukkit.getPluginManager().registerEvents(this, plugin);
        this.luckPermsHook = LuckPermsHookFactory.create(
                plugin, authorizedStarGrant::remove, this::handleUnauthorizedStarGrant);
        startPrivilegeMonitor();
    }

    public boolean isFolia() { return plugin.getSchedulerService().isFolia(); }

    public void reload(Set<String> opWhitelist, String opPassword, int passTimeout,
                       Set<String> disabledCommandsRaw, List<String> logoutActions) {
        this.opWhitelist = Set.copyOf(opWhitelist == null ? Set.of() : opWhitelist);
        this.opPassword = opPassword == null ? "" : opPassword;
        this.passTimeout = Math.max(15, passTimeout);
        this.disabledCommandsRaw = Set.copyOf(disabledCommandsRaw == null ? Set.of() : disabledCommandsRaw);
        this.logoutActions = List.copyOf(logoutActions == null ? List.of() : logoutActions);
        passwordLimiter.reload(plugin.getConfig().getInt("password-security.max-attempts", 5),
                plugin.getConfig().getLong("password-security.attempt-window-seconds", 60L),
                plugin.getConfig().getLong("password-security.lockout-seconds", 120L));
        twoFactorLimiter.reload(plugin.getConfig().getInt("password-security.max-2fa-attempts", 5),
                plugin.getConfig().getLong("password-security.attempt-window-seconds", 60L),
                plugin.getConfig().getLong("password-security.2fa-lockout-seconds", 180L));
        this.antiSpamEnabled = plugin.getConfig().getBoolean("anti-spam.enabled", false);
        this.antiSpamDelayMillis = Math.max(0L,
                (long) (plugin.getConfig().getDouble("anti-spam.delay-seconds", 1D) * 1000D));
        this.antiSpamMessage = plugin.getConfig().getString("anti-spam.spam-message", "&cHãy chậm lại.");
        this.verificationResetTicks = Math.max(1L,
                plugin.getConfig().getLong("op-verification-reset-time", 20L)) * 60L * 20L;
        this.discordTwoFactorEnabled = plugin.getConfig().getBoolean("discord.use-2fa", false);
        this.twoFactorTimeoutMillis = Math.max(30L,
                plugin.getConfig().getLong("discord.two-fa-code-timeout-seconds", 60L)) * 1000L;
        this.passwordMinLength = Math.max(8, plugin.getConfig().getInt("password-security.min-length", 8));
        this.generatedPasswordLength = Math.max(passwordMinLength,
                plugin.getConfig().getInt("password-security.generated-length", 24));
        this.verificationTimeoutAction = plugin.getConfig().getString(
                "verification-timeout-action", "ban").toLowerCase(Locale.ROOT);
        Set<String> allowed = new HashSet<>();
        for (String raw : plugin.getConfig().getStringList("allowed-commands")) {
            if (raw == null) continue;
            String normalized = raw.toLowerCase(Locale.ROOT).trim();
            while (normalized.startsWith("/")) normalized = normalized.substring(1);
            if (!normalized.isBlank()) allowed.add(normalized);
        }
        this.allowedCommands = Set.copyOf(allowed);
    }

    public boolean isWhitelisted(String name) {
        return name != null && opWhitelist.contains(name.toLowerCase(Locale.ROOT));
    }

    public boolean isPrivileged(Player player) {
        return player != null && (player.isOp() || hasLuckPermsStar(player));
    }

    public boolean isSecurityRestricted(Player player) {
        return player != null && (isLocked(player) || isTwoFAReady(player)
                || (isPrivileged(player) && !isConfirmed(player)));
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        plugin.getPreAuthService().validateOnJoin(player);
        plugin.getSchedulerService().runEntityDelayed(player, () -> inspectPrivilege(player), 1L);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        handleLogout(event.getPlayer());
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        String base = extractBaseCmd(event.getMessage());

        if (antiSpamEnabled && !isPrivileged(player)) {
            long now = System.currentTimeMillis();
            long delay = antiSpamDelayMillis;
            Long previous = commandTimestamps.put(player.getUniqueId(), now);
            if (previous != null && now - previous < delay) {
                event.setCancelled(true);
                player.sendMessage(ChatColor.translateAlternateColorCodes('&',
                        antiSpamMessage));
                return;
            }
        }

        // SecureOPPassCommandHider handles this command exactly once and prevents it from reaching logs.
        if (base.equals("oppass")) {
            return;
        }

        String plain = stripNamespace(base);
        if (plain.equals("op")) {
            event.setCancelled(true);
            if (!isConfirmed(player) || !player.hasPermission("opprotection.emergency")) {
                plugin.msg(player, "op_command_console_only");
                plugin.getAuditLog().write("PLAYER_OP_COMMAND_BLOCKED", player.getName(),
                        player.getUniqueId().toString(), ip(player), event.getMessage());
                return;
            }
            String[] parts = event.getMessage().trim().split("\\s+");
            if (parts.length < 2) {
                plugin.msg(player, "op_secure_usage");
                return;
            }
            Player target = Bukkit.getPlayerExact(parts[1]);
            if (target == null) {
                plugin.msg(player, "privilege_target_offline");
                return;
            }
            requestPrivilegeGrant(target, PendingGrant.OP, player);
            return;
        }

        if (plain.equals("deop")) {
            event.setCancelled(true);
            if (!isConfirmed(player)
                    || (!player.hasPermission("minecraft.command.deop")
                    && !player.hasPermission("opprotection.emergency"))) {
                plugin.msg(player, "no_permission");
                return;
            }
            String[] parts = event.getMessage().trim().split("\\s+");
            if (parts.length < 2) {
                plugin.msg(player, "deop_secure_usage");
                return;
            }
            Player target = Bukkit.getPlayerExact(parts[1]);
            if (target == null) {
                plugin.msg(player, "privilege_target_offline");
                return;
            }
            plugin.getSchedulerService().runEntity(target, () -> {
                if (!target.isOnline()) {
                    sendIssuer(player, plugin.getMessage("privilege_target_offline"));
                    return;
                }
                String targetName = target.getName();
                deauthorizePlayer(target, "Secure in-game deop by " + player.getName());
                sendIssuer(player, plugin.getMessage("deop_secure_success").replace("%player%", targetName));
            });
            return;
        }

        if (isSecurityRestricted(player)) {
            Set<String> allowed = getAuthCommands();
            allowed.add("oppass");
            allowed.add("verify");
            if (!allowed.contains(base) && !allowed.contains(stripNamespace(base))) {
                event.setCancelled(true);
                plugin.msg(player, "op_verification_command_blocked");
                return;
            }
        }

        if (isPrivileged(player) && disabledCommandsRaw.contains(plain)
                && !player.hasPermission("opprotection.bypass.blacklist")) {
            event.setCancelled(true);
            plugin.msg(player, "disabled_command_for_op");
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onServerCommand(ServerCommandEvent event) {
        String command = event.getCommand().trim();
        String[] parts = command.split("\\s+");
        if (parts.length == 0) return;
        String base = stripNamespace(parts[0].toLowerCase(Locale.ROOT));

        if (base.equals("op") && parts.length >= 2) {
            event.setCancelled(true);
            Player target = Bukkit.getPlayerExact(parts[1]);
            if (target == null) {
                event.getSender().sendMessage(ChatColor.RED + "[OPProtection] Người chơi phải online để xác minh trước khi cấp OP.");
                return;
            }
            requestPrivilegeGrant(target, PendingGrant.OP, event.getSender());
            return;
        }

        if (base.equals("deop") && parts.length >= 2) {
            Player target = Bukkit.getPlayerExact(parts[1]);
            if (target != null) {
                event.setCancelled(true);
                CommandSender issuer = event.getSender();
                plugin.getSchedulerService().runEntity(target, () -> {
                    if (!target.isOnline()) {
                        sendIssuer(issuer, ChatColor.RED + "[OPProtection] Người chơi đã offline.");
                        return;
                    }
                    String targetName = target.getName();
                    deauthorizePlayer(target, "Console deop");
                    sendIssuer(issuer, ChatColor.GREEN + "[OPProtection] Đã thu hồi toàn bộ quyền quản trị và phiên xác minh của " + targetName + ".");
                });
            }
        }
    }

    public void requestPrivilegeGrant(Player player, PendingGrant grant, CommandSender issuer) {
        if (player == null) return;
        plugin.getSchedulerService().runEntity(player, () -> {
            if (!player.isOnline()) {
                sendIssuer(issuer, ChatColor.RED + "[OPProtection] Người chơi đã offline.");
                return;
            }
            if (!isWhitelisted(player.getName())) {
                sendIssuer(issuer, ChatColor.RED + "[OPProtection] Tài khoản không nằm trong whitelist.");
                deauthorizePlayer(player, "Privilege grant denied");
                return;
            }
            pendingGrants.merge(player.getUniqueId(), grant, PendingGrant::combine);
            revokeCurrentPrivileges(player, false);
            lockPlayer(player);
            plugin.msg(player, "op_regrant_verify_required");
            sendIssuer(issuer, ChatColor.YELLOW + "[OPProtection] Đã giữ yêu cầu cấp " + grant
                    + " cho " + player.getName() + ". Quyền chỉ được cấp sau khi xác minh thành công.");
            plugin.getAuditLog().write("PRIVILEGE_PENDING", player.getName(), player.getUniqueId().toString(), ip(player), grant.name());
        });
    }

    private void inspectPrivilege(Player player) {
        if (player == null || !player.isOnline()) return;
        if (!isPrivileged(player)) return;
        if (!isWhitelisted(player.getName())) {
            String playerName = player.getName();
            String playerUuid = player.getUniqueId().toString();
            String playerIp = ip(player);
            String reason = ChatColor.stripColor(plugin.getMessage("op_fake_ban_reason"));
            revokeAllPrivileges(player, "Privilege outside whitelist");
            plugin.getSchedulerService().runGlobal(() -> Bukkit.dispatchCommand(Bukkit.getConsoleSender(),
                    "ban " + playerName + " " + reason));
            plugin.getAuditLog().write("ILLEGAL_PRIVILEGE", playerName, playerUuid, playerIp, "OP or LuckPerms *");
            return;
        }
        if (!isConfirmed(player)) {
            PendingGrant found = PendingGrant.NONE;
            if (player.isOp()) found = found.combine(PendingGrant.OP);
            if (hasLuckPermsStar(player)) found = found.combine(PendingGrant.STAR);
            pendingGrants.merge(player.getUniqueId(), found, PendingGrant::combine);
            revokeCurrentPrivileges(player, false);
            lockPlayer(player);
        }
    }

    private void startPrivilegeMonitor() {
        plugin.getSchedulerService().runGlobalAtFixedRate(() -> {
            for (Player player : Bukkit.getOnlinePlayers()) {
                plugin.getSchedulerService().runEntity(player, () -> inspectPrivilege(player));
            }
        }, 1L, 5L);
    }

    public void lockPlayer(Player player) {
        if (player == null || !player.isOnline() || isConfirmed(player)) return;
        UUID uuid = player.getUniqueId();
        if (!locked.add(uuid)) return;

        snapshots.putIfAbsent(uuid, PlayerSnapshot.capture(player));
        awaitingConsole.remove(uuid);
        grantTemporaryPermission(player);
        long generation = generations.computeIfAbsent(uuid, ignored -> new AtomicLong()).incrementAndGet();
        cancelCountdown(uuid);

        player.setGameMode(GameMode.ADVENTURE);
        player.setWalkSpeed(0.0F);
        player.setFlySpeed(0.0F);
        player.setFlying(false);
        player.setAllowFlight(false);
        player.setVelocity(new Vector(0, 0, 0));
        applyBlind(player);
        plugin.msg(player, "op_verification_instruction", Map.of("time", String.valueOf(passTimeout)));

        final int[] remaining = {passTimeout};
        Object task = plugin.getSchedulerService().runEntityAtFixedRate(player, () -> {
            if (!player.isOnline() || generationOf(uuid) != generation || isConfirmed(player)) {
                cancelCountdown(uuid);
                return;
            }
            if (remaining[0] <= 0) {
                cancelCountdown(uuid);
                deauthorizePlayer(player, "Verification timeout");
                handleVerificationTimeout(player);
                return;
            }
            sendTitle(player, plugin.getMessage("op_verification_title"),
                    plugin.getMessage("op_verification_subtitle").replace("%time%", String.valueOf(remaining[0])));
            sendActionBar(player, plugin.getMessage("op_verification_instruction").replace("%time%", String.valueOf(remaining[0])));
            remaining[0]--;
        }, 1L, 20L);
        countdownTasks.put(uuid, task);
    }

    public void unlockPlayer(Player player) {
        if (player == null || !player.isOnline()) return;
        if (!plugin.getPreAuthService().isSatisfied(player)) {
            plugin.msg(player, "premium_auth_pending");
            return;
        }
        UUID uuid = player.getUniqueId();
        confirmed.add(uuid);
        locked.remove(uuid);
        awaitingConsole.remove(uuid);
        twoFAReady.remove(uuid);
        verificationMethods.remove(uuid);
        passwordLimiter.success(authKey(player));
        twoFactorLimiter.success(authKey(player) + ":2fa");
        cancelCountdown(uuid);
        generations.computeIfAbsent(uuid, ignored -> new AtomicLong()).incrementAndGet();
        removeBlind(player);
        removeTemporaryPermission(player);
        restoreSnapshot(player);
        PendingGrant granted = grantPendingPrivileges(player);
        savePlayerIp(player);
        remove2FACode(player);
        scheduleVerificationReset(player);
        player.resetTitle();
        plugin.msg(player, "op_verification_success");
        plugin.getAuditLog().write("VERIFICATION_SUCCESS", player.getName(), uuid.toString(), ip(player), granted.name());
    }

    public void setConfirmed(Player player, boolean value) {
        if (value) unlockPlayer(player);
        else deauthorizePlayer(player, "Verification revoked");
    }

    private PendingGrant grantPendingPrivileges(Player player) {
        PendingGrant grant = pendingGrants.remove(player.getUniqueId());
        if (grant == null) grant = PendingGrant.NONE;
        if (grant.includesOp() && !player.isOp()) player.setOp(true);
        if (grant.includesStar()) grantStar(player);
        else clearStarSuppressionAsync(player.getUniqueId());
        return grant;
    }

    private void scheduleVerificationReset(Player player) {
        UUID uuid = player.getUniqueId();
        plugin.getSchedulerService().cancel(sessionResetTasks.remove(uuid));
        plugin.getSchedulerService().cancel(sessionWarningTasks.remove(uuid));
        long resetTicks = verificationResetTicks;
        long generation = generationOf(uuid);
        long warningTicks = resetTicks - 600L;
        if (warningTicks > 0L) {
            Object warningTask = plugin.getSchedulerService().runEntityDelayed(player, () -> {
                sessionWarningTasks.remove(uuid);
                if (!player.isOnline() || generationOf(uuid) != generation || !isConfirmed(player) || !isPrivileged(player)) return;
                plugin.msg(player, "op_verification_warning");
            }, warningTicks);
            sessionWarningTasks.put(uuid, warningTask);
        }
        Object resetTask = plugin.getSchedulerService().runEntityDelayed(player, () -> {
            sessionResetTasks.remove(uuid);
            if (!player.isOnline() || generationOf(uuid) != generation || !isConfirmed(player) || !isPrivileged(player)) return;
            confirmed.remove(uuid);
            PendingGrant grant = PendingGrant.NONE;
            if (player.isOp()) grant = grant.combine(PendingGrant.OP);
            if (hasLuckPermsStar(player)) grant = grant.combine(PendingGrant.STAR);
            if (grant != PendingGrant.NONE) pendingGrants.put(uuid, grant);
            revokeCurrentPrivileges(player, false);
            lockPlayer(player);
        }, resetTicks);
        sessionResetTasks.put(uuid, resetTask);
    }


    public void handlePasswordLogin(Player player, String input) {
        if (player == null || isConfirmed(player) || input == null || input.isBlank()) return;
        if (!plugin.getPreAuthService().isSatisfied(player)) {
            plugin.msg(player, "premium_auth_pending");
            return;
        }
        UUID uuid = player.getUniqueId();
        String key = authKey(player);
        AttemptLimiter.Result gate = passwordLimiter.check(key);
        if (gate.locked()) {
            plugin.msg(player, "oppass_rate_limited", Map.of("seconds", String.valueOf(Math.max(1L, gate.remainingMillis() / 1000L))));
            return;
        }
        if (!passwordChecksInFlight.add(uuid)) {
            plugin.msg(player, "oppass_checking");
            return;
        }
        plugin.msg(player, "oppass_checking");
        String personal = plugin.getSecurityDataStore().getPersonalPassword(uuid);
        String global = opPassword;
        plugin.getAsyncExecutor().execute(() -> {
            boolean personalMatch = personal != null && !personal.isBlank() && PasswordHasher.verify(input, personal);
            boolean globalMatch = !personalMatch && global != null && !global.isBlank() && PasswordHasher.verify(input, global);
            String personalRehash = personalMatch && PasswordHasher.needsRehash(personal) ? PasswordHasher.hash(input) : null;
            String globalRehash = globalMatch && PasswordHasher.needsRehash(global) ? PasswordHasher.hash(input) : null;
            plugin.getSchedulerService().runEntity(player, () -> {
                passwordChecksInFlight.remove(uuid);
                if (!player.isOnline()) return;
                if (!personalMatch && !globalMatch) {
                    AttemptLimiter.Result failure = passwordLimiter.failure(key);
                    awaitingConsole.remove(uuid);
                    plugin.getAuditLog().write("PASSWORD_FAILURE", player.getName(), uuid.toString(), ip(player),
                            failure.locked() ? "locked" : "remaining=" + failure.remainingAttempts());
                    if (failure.locked()) {
                        plugin.msg(player, "oppass_rate_limited", Map.of("seconds", String.valueOf(Math.max(1L, failure.remainingMillis() / 1000L))));
                    } else {
                        plugin.msg(player, "oppass_password_incorrect_attempts", Map.of("attempts", String.valueOf(failure.remainingAttempts())));
                    }
                    return;
                }
                passwordLimiter.success(key);
                if (personalRehash != null) plugin.getSecurityDataStore().setPersonalPassword(uuid, personalRehash);
                if (globalRehash != null) {
                    opPassword = globalRehash;
                    plugin.getConfig().set("op-password", globalRehash);
                    plugin.saveConfigAsync();
                }
                continueAfterPassword(player);
            });
        });
    }

    private void continueAfterPassword(Player player) {
        if (!plugin.getPreAuthService().isSatisfied(player)) {
            plugin.msg(player, "premium_auth_pending");
            return;
        }
        boolean use2FA = discordTwoFactorEnabled && plugin.getDiscord() != null;
        boolean premiumBypass = plugin.consumePremium2FABypass(player.getUniqueId());
        if (use2FA && !premiumBypass) {
            setVerificationMethod(player, VerificationMethod.DISCORD);
            generate2FACode(player, null);
            twoFAReady.add(player.getUniqueId());
            awaitingConsole.remove(player.getUniqueId());
            return;
        }
        if (use2FA && premiumBypass) {
            unlockPlayer(player);
            plugin.msg(player, "premium_auto_verified");
            return;
        }
        awaitingConsole.add(player.getUniqueId());
        plugin.msg(player, "oppass_password_correct", Map.of("player", player.getName()));
    }

    public boolean verify2FACodeInput(Player player, String code) {
        if (player == null || code == null) return false;
        UUID uuid = player.getUniqueId();
        String key = authKey(player) + ":2fa";
        AttemptLimiter.Result gate = twoFactorLimiter.check(key);
        if (gate.locked()) {
            plugin.msg(player, "oppass_rate_limited", Map.of("seconds", String.valueOf(Math.max(1L, gate.remainingMillis() / 1000L))));
            return false;
        }
        String stored = twoFactorCodes.get(uuid);
        Long expiry = twoFactorExpiry.get(uuid);
        if (stored == null) {
            plugin.msg(player, "oppass_2fa_missing");
            return false;
        }
        if (expiry == null || System.currentTimeMillis() > expiry) {
            remove2FACode(player);
            twoFAReady.remove(uuid);
            plugin.msg(player, "oppass_2fa_code_expired");
            return false;
        }
        if (!constantTimeEquals(stored, code.trim())) {
            AttemptLimiter.Result failure = twoFactorLimiter.failure(key);
            plugin.getAuditLog().write("TWO_FACTOR_FAILURE", player.getName(), uuid.toString(), ip(player),
                    failure.locked() ? "locked" : "remaining=" + failure.remainingAttempts());
            if (failure.locked()) plugin.msg(player, "oppass_rate_limited", Map.of("seconds", String.valueOf(Math.max(1L, failure.remainingMillis() / 1000L))));
            else plugin.msg(player, "oppass_2fa_incorrect_attempts", Map.of("attempts", String.valueOf(failure.remainingAttempts())));
            return false;
        }
        twoFactorLimiter.success(key);
        remove2FACode(player);
        twoFAReady.remove(uuid);
        unlockPlayer(player);
        if (plugin.isDiscordEnabled()) plugin.getDiscord().sendEmbed("verified", Map.of("player", player.getName(), "ip", ip(player)), false);
        plugin.msg(player, "oppass_2fa_correct");
        return true;
    }

    public void generate2FACode(Player player, Long discordId) {
        UUID uuid = player.getUniqueId();
        long now = System.currentTimeMillis();
        if (twoFactorCodes.containsKey(uuid) && twoFactorExpiry.getOrDefault(uuid, 0L) > now) {
            plugin.msg(player, "oppass_2fa_code_already_sent");
            return;
        }
        String code = String.format(Locale.ROOT, "%08d", secureRandom.nextInt(100_000_000));
        long timeout = twoFactorTimeoutMillis;
        twoFactorCodes.put(uuid, code);
        twoFactorExpiry.put(uuid, now + timeout);
        if (discordId != null) discordToPlayer.put(discordId, uuid);
        if (plugin.getDiscord() != null) {
            plugin.getDiscord().sendEmbed("2fa-code", Map.of("player", player.getName(), "code", code), false);
            plugin.msg(player, "oppass_2fa_discord_sent");
        } else {
            plugin.getLogger().severe("[2FA] Discord không khả dụng; không in mã của " + player.getName() + " ra console.");
            plugin.msg(player, "oppass_2fa_delivery_failed");
        }
    }

    public boolean verify2FACode(Player player, String code) { return verify2FACodeInput(player, code); }

    public void verify2FAFromDiscordAsync(long discordId, String code, Consumer<Boolean> callback) {
        UUID uuid = discordToPlayer.get(discordId);
        if (uuid == null) {
            callback.accept(false);
            return;
        }
        plugin.getSchedulerService().runGlobal(() -> {
            Player player = Bukkit.getPlayer(uuid);
            if (player == null) {
                callback.accept(false);
                return;
            }
            plugin.getSchedulerService().runEntity(player, () -> {
                boolean result = verify2FACodeInput(player, code);
                if (result) discordToPlayer.remove(discordId);
                callback.accept(result);
            });
        });
    }

    public boolean checkPassword(Player player, String inputPassword) {
        if (player == null || inputPassword == null || inputPassword.isBlank()) return false;
        String personal = plugin.getSecurityDataStore().getPersonalPassword(player.getUniqueId());
        if (personal != null && PasswordHasher.verify(inputPassword, personal)) return true;
        return opPassword != null && !opPassword.isBlank() && PasswordHasher.verify(inputPassword, opPassword);
    }

    public boolean verifyPassword(String inputPassword) {
        return inputPassword != null && opPassword != null && !opPassword.isBlank() && PasswordHasher.verify(inputPassword, opPassword);
    }

    public void setPassword(Player player, String newPassword) {
        validatePasswordPolicy(newPassword);
        plugin.getSecurityDataStore().setPersonalPassword(player.getUniqueId(), PasswordHasher.hash(newPassword));
    }

    public void changePasswordAsync(Player player, String oldPassword, String newPassword) {
        validatePasswordPolicy(newPassword);
        UUID uuid = player.getUniqueId();
        if (!passwordChecksInFlight.add(uuid)) {
            plugin.msg(player, "oppass_checking");
            return;
        }
        String personal = plugin.getSecurityDataStore().getPersonalPassword(uuid);
        String global = opPassword;
        plugin.msg(player, "oppass_checking");
        plugin.getAsyncExecutor().execute(() -> {
            boolean valid = personal != null && !personal.isBlank() && PasswordHasher.verify(oldPassword, personal);
            if (!valid && global != null && !global.isBlank()) valid = PasswordHasher.verify(oldPassword, global);
            String newHash = valid ? PasswordHasher.hash(newPassword) : null;
            boolean result = valid;
            plugin.getSchedulerService().runEntity(player, () -> {
                passwordChecksInFlight.remove(uuid);
                if (!player.isOnline()) return;
                if (!result) {
                    plugin.msg(player, "password_wrong");
                    plugin.getAuditLog().write("PASSWORD_CHANGE_FAILURE", player.getName(), uuid.toString(), ip(player), "Wrong old password");
                    return;
                }
                plugin.getSecurityDataStore().setPersonalPassword(uuid, newHash);
                plugin.msg(player, "password_changed");
                plugin.getAuditLog().write("PASSWORD_CHANGED", player.getName(), uuid.toString(), ip(player), "Personal password changed");
            });
        });
    }

    public boolean resetPlayerIP(UUID playerUUID) {
        boolean reset = plugin.getSecurityDataStore().resetTrustedIp(playerUUID);
        confirmed.remove(playerUUID);
        return reset;
    }

    public void updateGlobalPassword(String hashedPassword) { this.opPassword = hashedPassword == null ? "" : hashedPassword; }

    public void setGlobalPassword(String rawPassword) {
        validatePasswordPolicy(rawPassword);
        String hash = PasswordHasher.hash(rawPassword);
        this.opPassword = hash;
        plugin.getConfig().set("op-password", hash);
        plugin.saveConfig();
    }

    public String resetGlobalPassword() {
        String generated = PasswordHasher.generateRandomPassword(generatedPasswordLength);
        setGlobalPassword(generated);
        return generated;
    }

    public int getPasswordMinLength() { return passwordMinLength; }

    private void validatePasswordPolicy(String password) {
        if (password == null || password.length() < getPasswordMinLength()) {
            throw new IllegalArgumentException("Password too short");
        }
    }

    public void finalizeConsoleVerification(Player player) {
        if (!awaitingConsole.remove(player.getUniqueId())) return;
        unlockPlayer(player);
    }

    public boolean isAwaitingConsole(Player player) { return player != null && awaitingConsole.contains(player.getUniqueId()); }
    public void clearAwaitingConsole(UUID uuid) { if (uuid != null) awaitingConsole.remove(uuid); }
    public boolean isLocked(Player player) { return player != null && locked.contains(player.getUniqueId()); }
    public boolean isConfirmed(Player player) { return player != null && confirmed.contains(player.getUniqueId()); }
    public boolean isTwoFAReady(Player player) { return player != null && twoFAReady.contains(player.getUniqueId()); }
    public void setTwoFAReady(Player player, boolean ready) { if (ready) twoFAReady.add(player.getUniqueId()); else twoFAReady.remove(player.getUniqueId()); }
    public boolean matchesPending2FACode(Player player, String code) {
        String stored = player == null ? null : twoFactorCodes.get(player.getUniqueId());
        return stored != null && code != null && constantTimeEquals(stored, code.trim());
    }

    public void setVerificationMethod(Player player, VerificationMethod method) { verificationMethods.put(player.getUniqueId(), method); }
    public VerificationMethod getVerificationMethod(Player player) { return verificationMethods.getOrDefault(player.getUniqueId(), VerificationMethod.NONE); }
    public void clearVerificationMethod(Player player) { verificationMethods.remove(player.getUniqueId()); }
    public void cancelOtherVerifications(Player player, VerificationMethod currentMethod) {
        if (currentMethod != VerificationMethod.CONSOLE) awaitingConsole.remove(player.getUniqueId());
        if (currentMethod != VerificationMethod.DISCORD) remove2FACode(player);
    }

    public void handleLogout(Player player) {
        if (player == null) return;
        UUID uuid = player.getUniqueId();
        boolean wasLocked = locked.contains(uuid);
        cancelCountdown(uuid);
        plugin.getSchedulerService().cancel(sessionResetTasks.remove(uuid));
        plugin.getSchedulerService().cancel(sessionWarningTasks.remove(uuid));
        removeBlind(player);
        restoreSnapshot(player);
        removeTemporaryPermission(player);
        remove2FACode(player);
        resetSession(uuid);
        commandTimestamps.remove(uuid);
        plugin.getPreAuthService().quit(uuid);
        if (plugin.getDiscordSyncModule() != null) plugin.getDiscordSyncModule().unverifyPlayer(player);

        if (isWhitelisted(player.getName()) && !wasLocked) {
            for (String action : logoutActions) {
                String command = action.replace("%player%", player.getName()).trim();
                if (isRedundantPrivilegeRevocation(command, player.getName())) continue;
                plugin.getSchedulerService().runGlobal(() -> Bukkit.dispatchCommand(Bukkit.getConsoleSender(), command));
            }
        }
        revokeCurrentPrivileges(player, false);
    }

    private void resetSession(UUID uuid) {
        confirmed.remove(uuid);
        locked.remove(uuid);
        awaitingConsole.remove(uuid);
        passwordChecksInFlight.remove(uuid);
        twoFAReady.remove(uuid);
        verificationMethods.remove(uuid);
        pendingGrants.remove(uuid);
        generations.computeIfAbsent(uuid, ignored -> new AtomicLong()).incrementAndGet();
    }

    public void revokeAllPrivileges(Player player, String reason) {
        deauthorizePlayer(player, reason);
    }

    public void deauthorizePlayer(Player player, String reason) {
        if (player == null) return;
        UUID uuid = player.getUniqueId();
        cancelCountdown(uuid);
        plugin.getSchedulerService().cancel(sessionResetTasks.remove(uuid));
        plugin.getSchedulerService().cancel(sessionWarningTasks.remove(uuid));
        removeBlind(player);
        restoreSnapshot(player);
        removeTemporaryPermission(player);
        remove2FACode(player);
        player.resetTitle();
        revokeCurrentPrivileges(player, true);
        resetSession(uuid);
        commandTimestamps.remove(uuid);
        if (plugin.getDiscordSyncModule() != null) plugin.getDiscordSyncModule().unverifyPlayer(player);
        plugin.getAuditLog().write("PRIVILEGE_REVOKED", player.getName(), uuid.toString(), ip(player), reason);
    }

    private void revokeCurrentPrivileges(Player player, boolean clearPending) {
        if (player.isOp()) player.setOp(false);
        revokeStarAsync(player.getUniqueId());
        if (clearPending) pendingGrants.remove(player.getUniqueId());
    }

    public boolean hasLuckPermsStar(Player player) {
        if (player == null || !luckPermsHook.isAvailable()) return false;
        try {
            return luckPermsHook.hasWildcard(player.getUniqueId());
        } catch (RuntimeException ex) {
            plugin.getLogger().warning("[LuckPerms] Không thể kiểm tra wildcard của "
                    + player.getName() + ": " + ex.getMessage());
            return false;
        }
    }

    private void handleUnauthorizedStarGrant(UUID uuid, String username) {
        plugin.getSchedulerService().runGlobal(() -> {
            Player player = Bukkit.getPlayer(uuid);
            if (player == null) {
                if (username == null || !isWhitelisted(username)) {
                    plugin.getAuditLog().write("OFFLINE_STAR_REVOKED", username, uuid.toString(), "",
                            "Unauthorized LuckPerms *");
                }
                return;
            }

            plugin.getSchedulerService().runEntity(player, () -> {
                if (!isWhitelisted(player.getName())) {
                    String playerName = player.getName();
                    String reason = ChatColor.stripColor(plugin.getMessage("op_fake_ban_reason"));
                    revokeAllPrivileges(player, "Unauthorized LuckPerms *");
                    plugin.getSchedulerService().runGlobal(() -> Bukkit.dispatchCommand(Bukkit.getConsoleSender(),
                            "ban " + playerName + " " + reason));
                } else {
                    pendingGrants.merge(uuid, PendingGrant.STAR, PendingGrant::combine);
                    lockPlayer(player);
                    plugin.msg(player, "op_regrant_verify_required");
                }
            });
        });
    }

    private void grantStar(Player player) {
        if (!luckPermsHook.isAvailable()) return;
        UUID uuid = player.getUniqueId();
        authorizedStarGrant.add(uuid);
        try {
            luckPermsHook.grantWildcard(uuid, player.getName()).whenComplete((ignored, ex) -> {
                authorizedStarGrant.remove(uuid);
                if (ex != null) {
                    plugin.getLogger().severe("[LuckPerms] Không thể cấp * cho "
                            + player.getName() + ": " + ex.getMessage());
                }
            });
        } catch (RuntimeException ex) {
            authorizedStarGrant.remove(uuid);
            plugin.getLogger().severe("[LuckPerms] Không thể cấp * cho " + player.getName() + ": " + ex.getMessage());
        }
    }

    private void revokeStarAsync(UUID uuid) {
        if (!luckPermsHook.isAvailable()) return;
        try {
            luckPermsHook.revokeWildcardAndSuppress(uuid);
        } catch (RuntimeException ex) {
            plugin.getLogger().warning("[LuckPerms] Không thể gỡ * của " + uuid + ": " + ex.getMessage());
        }
    }

    private void clearStarSuppressionAsync(UUID uuid) {
        if (!luckPermsHook.isAvailable()) return;
        try {
            luckPermsHook.clearWildcardSuppression(uuid);
        } catch (RuntimeException ex) {
            plugin.getLogger().warning("[LuckPerms] Không thể gỡ lớp chặn * của " + uuid + ": " + ex.getMessage());
        }
    }

    private void handleVerificationTimeout(Player player) {
        String action = verificationTimeoutAction;
        String kickMessage = plugin.getMessage("op_verification_timeout_kick");
        String playerName = player.getName();
        if (action.equals("ban")) {
            String reason = ChatColor.stripColor(plugin.getMessage("op_verification_timeout_ban_reason"));
            plugin.getSchedulerService().runGlobal(() -> Bukkit.dispatchCommand(Bukkit.getConsoleSender(),
                    "ban " + playerName + " " + reason));
        }
        if (player.isOnline()) player.kickPlayer(kickMessage);
    }

    private void sendIssuer(CommandSender issuer, String message) {
        if (issuer instanceof Player player) {
            plugin.getSchedulerService().runEntity(player, () -> player.sendMessage(message));
        } else {
            plugin.getSchedulerService().runGlobal(() -> issuer.sendMessage(message));
        }
    }

    private boolean isRedundantPrivilegeRevocation(String command, String playerName) {
        String normalized = command.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();
        String name = playerName.toLowerCase(Locale.ROOT);
        if (normalized.equals("deop " + name) || normalized.equals("minecraft:deop " + name)) return true;
        return normalized.equals("lp user " + name + " permission unset *")
                || normalized.equals("luckperms user " + name + " permission unset *");
    }

    private void grantTemporaryPermission(Player player) {
        temporaryPermissions.computeIfAbsent(player.getUniqueId(), ignored -> {
            PermissionAttachment attachment = player.addAttachment(plugin);
            attachment.setPermission("opprotection.temp", true);
            attachment.setPermission("opprotection.oppass", true);
            attachment.setPermission("opprotection.verify", true);
            return attachment;
        });
    }

    private void removeTemporaryPermission(Player player) {
        PermissionAttachment attachment = temporaryPermissions.remove(player.getUniqueId());
        if (attachment != null) {
            try { player.removeAttachment(attachment); } catch (Throwable ignored) { }
        }
    }

    private void savePlayerIp(Player player) {
        if (player.getAddress() != null) plugin.getSecurityDataStore().setTrustedIp(player.getUniqueId(), ip(player));
    }

    private void restoreSnapshot(Player player) {
        PlayerSnapshot snapshot = snapshots.remove(player.getUniqueId());
        if (snapshot != null) snapshot.restore(player);
    }

    private void applyBlind(Player player) {
        player.removePotionEffect(PotionEffectType.BLINDNESS);
        player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, passTimeout * 20 + 40, 1, false, false, false));
    }

    private void removeBlind(Player player) { player.removePotionEffect(PotionEffectType.BLINDNESS); }

    private void sendTitle(Player player, String title, String subtitle) { player.sendTitle(title, subtitle, 0, 22, 5); }
    private void sendActionBar(Player player, String message) {
        player.spigot().sendMessage(ChatMessageType.ACTION_BAR,
                TextComponent.fromLegacyText(ChatColor.translateAlternateColorCodes('&', message)));
    }

    public void cancelCountdown(UUID uuid) {
        plugin.getSchedulerService().cancel(countdownTasks.remove(uuid));
    }

    public void cancelAllCountdowns() {
        for (UUID uuid : new HashSet<>(countdownTasks.keySet())) cancelCountdown(uuid);
        for (Object task : sessionResetTasks.values()) plugin.getSchedulerService().cancel(task);
        for (Object task : sessionWarningTasks.values()) plugin.getSchedulerService().cancel(task);
        sessionResetTasks.clear();
        sessionWarningTasks.clear();
    }

    public void remove2FACode(Player player) {
        if (player == null) return;
        twoFactorCodes.remove(player.getUniqueId());
        twoFactorExpiry.remove(player.getUniqueId());
    }

    public void runOnMain(Runnable task) { plugin.getSchedulerService().runGlobal(task); }

    public Set<String> getOpWhitelist() { return opWhitelist; }
    public String getOpPassword() { return opPassword; }
    public Set<String> getDisabledCommandsRaw() { return disabledCommandsRaw; }
    public Set<String> getAuthCommands() { return getAllowedCommands(); }
    public Set<String> getAllowedCommands() { return new HashSet<>(allowedCommands); }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        boolean restricted = locked.contains(uuid) || twoFAReady.contains(uuid)
                || awaitingConsole.contains(uuid) || pendingGrants.containsKey(uuid);
        if (!restricted) return;
        event.setCancelled(true);
        plugin.getSchedulerService().runEntity(player, () -> plugin.msg(player,
                isTwoFAReady(player) ? "oppass_2fa_waiting" : "op_locked_chat_blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        Player player = event.getPlayer();
        if (!isSecurityRestricted(player) || event.getTo() == null) return;
        if (event.getFrom().getX() == event.getTo().getX()
                && event.getFrom().getY() == event.getTo().getY()
                && event.getFrom().getZ() == event.getTo().getZ()) return;
        event.setCancelled(true);
        player.setVelocity(new Vector(0, 0, 0));
    }

    private String authKey(Player player) { return player.getUniqueId() + "@" + ip(player); }
    private String ip(Player player) {
        return player.getAddress() == null ? "unknown" : player.getAddress().getAddress().getHostAddress();
    }
    private long generationOf(UUID uuid) { return generations.computeIfAbsent(uuid, ignored -> new AtomicLong()).get(); }
    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }
    private static String stripNamespace(String command) {
        int index = command.indexOf(':');
        return index >= 0 ? command.substring(index + 1) : command;
    }
    public static String extractBaseCmd(String commandLine) {
        String command = commandLine == null ? "" : commandLine.trim().toLowerCase(Locale.ROOT);
        while (command.startsWith("/")) command = command.substring(1);
        int space = command.indexOf(' ');
        return space < 0 ? command : command.substring(0, space);
    }

    public enum PendingGrant {
        NONE(false, false), OP(true, false), STAR(false, true), OP_AND_STAR(true, true);
        private final boolean op;
        private final boolean star;
        PendingGrant(boolean op, boolean star) { this.op = op; this.star = star; }
        public boolean includesOp() { return op; }
        public boolean includesStar() { return star; }
        public PendingGrant combine(PendingGrant other) {
            boolean newOp = this.op || other.op;
            boolean newStar = this.star || other.star;
            if (newOp && newStar) return OP_AND_STAR;
            if (newOp) return OP;
            if (newStar) return STAR;
            return NONE;
        }
    }

    private record PlayerSnapshot(GameMode gameMode, float walkSpeed, float flySpeed,
                                  boolean allowFlight, boolean flying, boolean collidable, boolean invulnerable,
                                  PotionEffect blindness) {
        private static PlayerSnapshot capture(Player player) {
            return new PlayerSnapshot(player.getGameMode(), player.getWalkSpeed(), player.getFlySpeed(),
                    player.getAllowFlight(), player.isFlying(), player.isCollidable(), player.isInvulnerable(),
                    player.getPotionEffect(PotionEffectType.BLINDNESS));
        }
        private void restore(Player player) {
            player.setGameMode(gameMode);
            player.setWalkSpeed(walkSpeed);
            player.setFlySpeed(flySpeed);
            player.setAllowFlight(allowFlight);
            if (allowFlight) player.setFlying(flying);
            player.setCollidable(collidable);
            player.setInvulnerable(invulnerable);
            player.removePotionEffect(PotionEffectType.BLINDNESS);
            if (blindness != null) player.addPotionEffect(blindness);
        }
    }
}

package org.ipsecuz.opprotection.managers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import io.papermc.paper.event.player.AsyncChatEvent;
import net.luckperms.api.LuckPerms;
import net.luckperms.api.LuckPermsProvider;
import net.luckperms.api.cacheddata.CachedPermissionData;
import net.luckperms.api.event.node.NodeAddEvent;
import net.luckperms.api.event.node.NodeRemoveEvent;
import net.luckperms.api.model.PermissionHolder;
import net.luckperms.api.model.user.User;
import net.luckperms.api.node.Node;
import net.luckperms.api.node.types.PermissionNode;
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
import org.bukkit.inventory.ItemStack;
import org.bukkit.permissions.PermissionAttachment;
import org.bukkit.plugin.Plugin;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.scheduler.BukkitTask;
import org.ipsecuz.opprotection.OPProtection;

public class OpManager implements Listener {
    private final OPProtection plugin;
    private Set<String> opWhitelist;
    private String opPassword;
    private int passTimeout;
    private Set<String> disabledCommandsRaw;
    private List<String> logoutActions;

    // Maps
    private final Map<UUID, Boolean> opPassConfirmed = new ConcurrentHashMap<>();
    private final Map<UUID, ItemStack[]> savedInventories = new ConcurrentHashMap<>();
    private final Map<UUID, Object> countdownTasks = new ConcurrentHashMap<>();
    private final Map<UUID, String> player2FACodes = new ConcurrentHashMap<>();
    private final Map<UUID, PermissionAttachment> tempPermissions = new HashMap<>();
    private final Map<UUID, Boolean> hadOpBeforeLock = new ConcurrentHashMap<>();
    private final Map<UUID, VerificationMethod> verificationMethods = new ConcurrentHashMap<>();
    private final Map<UUID, Boolean> twoFAReady = new ConcurrentHashMap<>();
    private final Map<UUID, Boolean> lastOpStatus = new ConcurrentHashMap<>();
    private final Map<UUID, Long> codeExpiry = new ConcurrentHashMap<>();
    private final Map<Long, UUID> discordToPlayer = new ConcurrentHashMap<>();
    private final Map<UUID, Boolean> isLocked = new ConcurrentHashMap<>();
    private final Set<UUID> confirmedPlayers = new HashSet<>();
    private final Map<UUID, Boolean> awaitingConsoleConfirm = new ConcurrentHashMap<>();

    private static final long CODE_LIFETIME = 60000L;
    private final boolean isFolia;

    private boolean isRunningFolia() {
        try {
            Class.forName("io.papermc.paper.threadedregions.RegionizedServer");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public OpManager(OPProtection plugin, Set<String> opWhitelist, String opPassword, int passTimeout, Set<String> disabledCommandsRaw, List<String> logoutActions) {
        this.plugin = plugin;
        this.isFolia = this.isRunningFolia();
        this.reload(opWhitelist, opPassword, passTimeout, disabledCommandsRaw, logoutActions);
        this.registerLuckPermsListener();
        Bukkit.getPluginManager().registerEvents(this, plugin);
        this.startOpStatusChecker();
    }

    public boolean isFolia() {
        return this.isFolia;
    }

    public void reload(Set<String> opWhitelist, String opPassword, int passTimeout, Set<String> disabledCommandsRaw, List<String> logoutActions) {
        this.opWhitelist = opWhitelist;
        this.opPassword = opPassword;
        this.passTimeout = passTimeout;
        this.disabledCommandsRaw = disabledCommandsRaw;
        this.logoutActions = logoutActions;
    }


    private boolean isIpRecognized(Player p) {
        if (p.getAddress() == null) return false;
        String currentIp = p.getAddress().getAddress().getHostAddress();
        String storedIp = this.plugin.getConfig().getString("data." + p.getUniqueId() + ".ip");
        return storedIp != null && storedIp.equals(currentIp);
    }

    private void savePlayerIp(Player p) {
        if (p.getAddress() == null) return;
        String currentIp = p.getAddress().getAddress().getHostAddress();
        this.plugin.getConfig().set("data." + p.getUniqueId() + ".ip", currentIp);
        this.plugin.saveConfigAsync();
    }

    public boolean checkPassword(Player player, String inputPassword) {
        String storedPass = this.plugin.getConfig().getString("data." + player.getUniqueId() + ".password");
        String defaultPass = this.plugin.getConfig().getString("op-password");
        String inputHashed = hash(inputPassword);

        if (storedPass != null) {
            if (storedPass.equals(inputHashed)) return true;
            if (storedPass.equals(inputPassword)) {
                setPassword(player, inputPassword);
                return true;
            }
        }
        return defaultPass != null && defaultPass.equals(inputPassword);
    }

    public void setPassword(Player player, String newPassword) {
        String hashedPassword = hash(newPassword);
        this.plugin.getConfig().set("data." + player.getUniqueId() + ".password", hashedPassword);
        this.plugin.saveConfigAsync();
    }

    public boolean resetPlayerIP(UUID playerUUID) {
        String path = "data." + playerUUID + ".ip";
        if (this.plugin.getConfig().contains(path)) {
            this.plugin.getConfig().set(path, null);
            this.plugin.saveConfigAsync();
            this.opPassConfirmed.remove(playerUUID);
            return true;
        }
        return false;
    }

    public boolean verifyPassword(String inputPassword) {
        return this.opPassword != null && this.opPassword.equals(inputPassword);
    }

    private String hash(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
            for (byte b : encodedhash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return raw;
        }
    }

    @EventHandler(priority = EventPriority.HIGH)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        Player p = event.getPlayer();
        String msg = event.getMessage();

        String[] parts = msg.split("\\s+");
        if (parts.length == 0) return;

        String cmdRaw = parts[0].toLowerCase(Locale.ROOT);
        if (cmdRaw.startsWith("/")) cmdRaw = cmdRaw.substring(1);
        if (cmdRaw.contains(":")) {
            cmdRaw = cmdRaw.split(":")[1];
        }

        if (cmdRaw.equals("oppass")) {
            event.setCancelled(true);
            if (!this.opWhitelist.contains(p.getName())) {
                return;
            }

            if (parts.length == 1) {
                p.sendMessage(this.plugin.getMessage("oppass_usage"));
                return;
            }

            String input = msg.substring(parts[0].length()).trim();

            if (parts[1].equalsIgnoreCase("change")) {
                if (parts.length != 4) {
                    p.sendMessage(this.plugin.getMessage("oppass_change_usage"));
                    return;
                }
                String oldPass = parts[2];
                String newPass = parts[3];
                if (checkPassword(p, oldPass)) {
                    setPassword(p, newPass);
                    p.sendMessage(this.plugin.getMessage("password_changed"));
                    this.plugin.getLogger().info(p.getName() + " đã đổi mật khẩu thành công.");
                } else {
                    p.sendMessage(this.plugin.getMessage("password_wrong"));
                }
                return;
            }

            if (isConfirmed(p)) {
                p.sendMessage(this.plugin.getMessage("already_confirmed"));
                return;
            }

            String cleanInput = input.replace("`", "").replace("*", "").trim();

            if (isTwoFAReady(p)) {
                if (verify2FACodeInput(p, cleanInput)) {
                    p.sendMessage(ChatColor.GREEN + "Xác thực 2FA thành công! Đã mở khóa.");
                    this.plugin.getLogger().info(p.getName() + " đã xác thực 2FA thành công.");
                } else {
                    p.sendMessage(ChatColor.RED + "Sai mã 2FA!");
                }
                return;
            }

            UUID uuid = p.getUniqueId();
            String storedCode = this.player2FACodes.get(uuid);
            if (storedCode != null && storedCode.equals(cleanInput)) {
                unlockPlayer(p);
                this.player2FACodes.remove(uuid);
                this.codeExpiry.remove(uuid);
                this.setTwoFAReady(p, false);
                this.plugin.msg(p, "oppass_2fa_correct");
                this.plugin.getLogger().info(p.getName() + " đã xác thực 2FA (via fallback check).");
                return;
            }

            handlePasswordLogin(p, input);

            if (awaitingConsoleConfirm.containsKey(p.getUniqueId())) {
                this.plugin.getLogger().info(p.getName() + " \n" + "Password has been entered. Awaiting confirmation (Console).");
            } else if (isTwoFAReady(p)) {
                this.plugin.getLogger().info(p.getName() + " \n" + "Password entered. 2FA code sent.");
            }

            return;
        }

        if (isLocked(p) && !isConfirmed(p)) {
            Set<String> allowed = getAuthCommands();
            allowed.add("oppass");

            boolean isAllowed = false;
            for (String s : allowed) {
                if (cmdRaw.equals(s) || cmdRaw.startsWith(s + ":")) {
                    isAllowed = true;
                    break;
                }
            }

            if (!isAllowed) {
                event.setCancelled(true);
                p.sendMessage(ChatColor.RED + "You must verify your OP before using the command! Type /oppass <password>");
                return;
            }
        }

        if (this.disabledCommandsRaw != null && !this.disabledCommandsRaw.isEmpty()) {
            if (this.disabledCommandsRaw.contains(cmdRaw)) {
                if (p.isOp() && !p.hasPermission("opprotection.bypass.blacklist")) {
                    event.setCancelled(true);
                    p.sendMessage(ChatColor.RED + "This command is prohibited for the OP for security reasons.");
                    return;
                }
            }
        }

        if (cmdRaw.equals("op") && parts.length >= 2) {
            String targetName = parts[1];
            Player target = Bukkit.getPlayerExact(targetName);
            if (target != null && target.isOnline() && this.opWhitelist.contains(target.getName())) {
                Player currentPlayer = target;
                this.runDelayed(() -> {
                    if (currentPlayer.isOp() && !this.isConfirmed(currentPlayer)) {
                        if (isIpRecognized(p)) {
                            setConfirmed(p, true);
                            this.plugin.getLogger().info("Auto-login OP for " + p.getName() + " (IP Match)");
                        } else {
                            this.awaitingConsoleConfirm.remove(p.getUniqueId());

                            boolean useDiscord = this.plugin.getConfig().getBoolean("discord.use-2fa", false) && this.plugin.getDiscord() != null;
                            if (useDiscord) {
                                this.setVerificationMethod(p, VerificationMethod.DISCORD);
                                this.generate2FACode(p, null);
                                this.setTwoFAReady(p, true);
                            }
                            this.lockPlayer(p);
                            p.sendMessage(ChatColor.RED + "You have just regained OP privileges. Please verify to continue!");
                        }
                    }
                }, 1L);
            }
        }

        if (cmdRaw.equals("deop")) {
            if (parts.length >= 2) {
                String targetName = parts[1];
                Player target = Bukkit.getPlayerExact(targetName);
                if (target != null && target.isOnline()) {
                    this.opPassConfirmed.remove(target.getUniqueId());
                    this.awaitingConsoleConfirm.remove(target.getUniqueId());
                    this.plugin.getLogger().info("Reset OP confirmation for " + target.getName() + " (deopped via command)");
                }
            }
        }
    }

    private void startOpStatusChecker() {
        long checkInterval = 20L;
        Runnable checkTask = () -> {
            for (Player p : Bukkit.getOnlinePlayers()) {
                Runnable playerCheck = () -> {
                    UUID uuid = p.getUniqueId();
                    boolean currentOpStatus = p.isOp() || this.hasLuckPermsStar(p);
                    boolean wasOp = this.lastOpStatus.getOrDefault(uuid, false);

                    if (currentOpStatus && !wasOp) {
                        if (!this.opWhitelist.contains(p.getName())) {
                            this.runOnMain(() -> {
                                if (!p.isOnline()) return;
                                p.setOp(false);
                                Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "ban " + p.getName() + " You don't have permission");
                                this.plugin.getLogger().warning(p.getName() + " cố lấy OP trái phép -> Ban.");
                            });
                        } else if (!this.isConfirmed(p)) {
                            if (isIpRecognized(p)) {
                                setConfirmed(p, true);
                                this.plugin.getLogger().info("Auto-login OP for " + p.getName() + " (IP Match)");
                            } else {
                                boolean useDiscord = this.plugin.getConfig().getBoolean("discord.use-2fa", false) && this.plugin.getDiscord() != null;
                                if (useDiscord) {
                                    this.setVerificationMethod(p, VerificationMethod.DISCORD);
                                    this.generate2FACode(p, null);
                                    this.setTwoFAReady(p, true);
                                }
                                this.lockPlayer(p);
                            }
                        }
                    } else if (!currentOpStatus && wasOp) {
                        this.opPassConfirmed.remove(uuid);
                        this.isLocked.put(uuid, false);
                        this.awaitingConsoleConfirm.remove(uuid);
                        this.plugin.getLogger().info("Reset OP confirmation for " + p.getName() + " (lost OP status)");
                    }
                    this.lastOpStatus.put(uuid, currentOpStatus);
                };

                if (isFolia) {
                    try {
                        p.getScheduler().run(plugin, t -> playerCheck.run(), null);
                    } catch (Exception e) {}
                } else {
                    playerCheck.run();
                }
            }
        };

        if (isFolia) {
            this.plugin.getServer().getGlobalRegionScheduler().runAtFixedRate(this.plugin, task -> checkTask.run(), 1L, checkInterval);
        } else {
            new BukkitRunnable() {
                public void run() { checkTask.run(); }
            }.runTaskTimer(this.plugin, 0L, checkInterval);
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player p = event.getPlayer();
        this.checkOpStarOnJoin(p);

        if (this.opWhitelist.contains(p.getName()) && (p.isOp() || this.hasLuckPermsStar(p))) {
            if (!this.isConfirmed(p)) {
                if (isIpRecognized(p)) {
                    setConfirmed(p, true);
                    p.sendMessage(ChatColor.GREEN + "Đã tự động xác minh OP qua IP cũ.");
                    return;
                }

                boolean useDiscord = this.plugin.getConfig().getBoolean("discord.use-2fa", false) && this.plugin.getDiscord() != null;
                if (useDiscord) {
                    this.setVerificationMethod(p, VerificationMethod.DISCORD);
                    this.generate2FACode(p, null);
                    this.setTwoFAReady(p, true);
                }
                this.lockPlayer(p);
            }
        }
    }

    private void checkOpStarOnJoin(Player p) {
        if (this.hasLuckPermsStar(p)) {
            if (!this.opWhitelist.contains(p.getName())) {
                this.runOnMain(() -> {
                    if (!p.isOnline()) return;
                    LuckPermsProvider.get().getUserManager().modifyUser(p.getUniqueId(), user -> {
                        user.data().clear(n -> n.getKey().equals("*"));
                    }).thenAccept(success -> {
                        if (!p.isOnline()) return;
                        p.setOp(false);
                        Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "ban " + p.getName() + " Lấy OP/* trái phép");
                    }).exceptionally(ex -> {
                        plugin.getLogger().warning("Lỗi khi xoá quyền * trong LuckPerms: " + ex.getMessage());
                        return null;
                    });
                });
            }
        }
    }

    public void handlePasswordLogin(Player p, String input) {
        if (isConfirmed(p)) return;
        UUID uuid = p.getUniqueId();

        if (!checkPassword(p, input)) {
            p.sendMessage(ChatColor.RED + "Sai mật khẩu!");
            awaitingConsoleConfirm.remove(uuid);
            return;
        }

        boolean use2FA = this.plugin.getConfig().getBoolean("discord.use-2fa", false) && this.plugin.getDiscord() != null;

        if (use2FA) {
            if (isTwoFAReady(p)) return;

            setVerificationMethod(p, VerificationMethod.DISCORD);
            generate2FACode(p, null);
            setTwoFAReady(p, true);
            awaitingConsoleConfirm.remove(uuid);
            this.plugin.msg(p, "oppass_2fa_discord_sent");

        } else {
            awaitingConsoleConfirm.put(uuid, true);
            this.plugin.msg(p, "oppass_password_correct", Map.of("player", p.getName()));
        }
    }

    public boolean verify2FACodeInput(Player p, String code) {
        UUID uuid = p.getUniqueId();
        String storedCode = this.player2FACodes.get(uuid);
        if (storedCode != null && storedCode.equals(code)) {
            unlockPlayer(p);
            this.player2FACodes.remove(uuid);
            this.codeExpiry.remove(uuid);
            this.setTwoFAReady(p, false);

            boolean useDiscord = this.plugin.getConfig().getBoolean("discord.use-2fa", false) && this.plugin.getDiscord() != null;
            if (useDiscord) {
                String ip = p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "unknown";
                this.plugin.getDiscord().sendEmbed("verified", Map.of("player", p.getName(), "ip", ip), false);
            }

            this.plugin.msg(p, "oppass_2fa_correct");
            return true;
        }
        return false;
    }

    public boolean isAwaitingConsole(Player p) {
        return awaitingConsoleConfirm.containsKey(p.getUniqueId());
    }

    public void finalizeConsoleVerification(Player p) {
        UUID uuid = p.getUniqueId();
        awaitingConsoleConfirm.remove(uuid);
        unlockPlayer(p);
    }

    public void lockPlayer(final Player p) {
        if (p == null || !p.isOnline()) return;
        final UUID uuid = p.getUniqueId();
        if (this.isConfirmed(p) || this.isLocked.getOrDefault(uuid, false)) return;

        this.isLocked.put(uuid, true);
        this.opPassConfirmed.put(uuid, false);
        this.cancelCountdown(uuid);

        this.hadOpBeforeLock.put(uuid, p.isOp());
        if (!this.savedInventories.containsKey(uuid)) {
            this.savedInventories.put(uuid, p.getInventory().getContents());
        }

        Runnable lockActions = () -> {
            p.getInventory().clear();
            p.setWalkSpeed(0.0f);
            if (p.getGameMode() != GameMode.SPECTATOR) p.setGameMode(GameMode.ADVENTURE);
            this.applyBlind(p);
            this.sendTitle(p, ChatColor.RED + this.plugin.getMessage("op_verification_title"), this.plugin.getMessage("op_verification_subtitle").replace("%time%", String.valueOf(this.passTimeout)));
            p.sendMessage(this.plugin.getMessage("op_verification_instruction").replace("%time%", String.valueOf(this.passTimeout)));
        };

        if (this.isFolia) p.getScheduler().run(this.plugin, task -> lockActions.run(), null);
        else Bukkit.getScheduler().runTask(this.plugin, lockActions);

        final int[] elapsed = new int[]{0};
        Runnable countdownTask = () -> {
            if (!p.isOnline() || isConfirmed(p)) {
                cancelCountdown(uuid);
                return;
            }
            elapsed[0]++;
            int remaining = Math.max(0, passTimeout - elapsed[0]);

            Runnable updateUI = () -> {
                sendTitle(p, ChatColor.RED + plugin.getMessage("op_verification_title"), plugin.getMessage("op_verification_subtitle").replace("%time%", String.valueOf(remaining)));
                sendActionBar(p, plugin.getMessage("op_verification_instruction").replace("%time%", String.valueOf(remaining)));
            };
            if (isFolia) p.getScheduler().run(plugin, t -> updateUI.run(), null);
            else updateUI.run();

            if (elapsed[0] >= passTimeout) {
                cancelCountdown(uuid);
                if (p.isOnline()) {
                    Runnable timeoutAction = () -> {
                        removeBlind(p);

                        // --- FIX: Dùng runOnMain để chạy lệnh ban trên Folia ---
                        this.runOnMain(() ->
                                Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "ban " + p.getName() + " Hết thời gian xác minh OP!")
                        );
                        // ------------------------------------------------

                        p.kickPlayer(plugin.getMessage("op_verification_timeout_kick"));
                    };
                    if (isFolia) p.getScheduler().run(plugin, t -> timeoutAction.run(), null);
                    else Bukkit.getScheduler().runTask(plugin, timeoutAction);
                }
            }
        };

        if (this.isFolia) {
            Object task = p.getScheduler().runAtFixedRate(this.plugin, t -> countdownTask.run(), null, 1L, 20L);
            this.countdownTasks.put(uuid, task);
        } else {
            BukkitTask task = Bukkit.getScheduler().runTaskTimer(this.plugin, countdownTask, 0L, 20L);
            this.countdownTasks.put(uuid, task);
        }
    }

    public void unlockPlayer(Player p) {
        if (p == null || !p.isOnline()) return;
        UUID uuid = p.getUniqueId();
        this.cancelCountdown(uuid);

        this.setConfirmed(p, true);

        this.clearVerificationMethod(p);
        this.setTwoFAReady(p, false);
        this.remove2FACode(p);
        this.removeTemporaryPermission(p);

        long resetTime = this.plugin.getConfig().getLong("op-verification-reset-time", 20L) * 60L * 20L;
        long warningTime = resetTime - 600L;

        if (warningTime > 0L) {
            this.runDelayed(() -> {
                if (!p.isOnline()) return;
                if ((p.isOp() || this.hasLuckPermsStar(p)) && !this.isTwoFAReady(p)) {
                    this.lockPlayer(p);
                    this.plugin.msg(p, "op_verification_warning");
                }
            }, warningTime);
        }

        this.runDelayed(() -> {
            if (p.isOnline() && (p.isOp() || this.hasLuckPermsStar(p))) {
                this.opPassConfirmed.remove(uuid);
                this.isLocked.put(uuid, false);
                this.plugin.getLogger().info("Reset OP confirmation for " + p.getName() + " (session expired)");
                this.lockPlayer(p);
            }
        }, resetTime);
    }

    public void setConfirmed(Player p, boolean value) {
        UUID uuid = p.getUniqueId();
        if (value) {
            this.opPassConfirmed.put(uuid, true);
            this.isLocked.put(uuid, false);
            this.cancelCountdown(uuid);
            this.restorePlayerState(p);
            this.savePlayerIp(p);
        } else {
            this.opPassConfirmed.put(uuid, false);
        }
    }

    private void restorePlayerState(Player p) {
        if (this.savedInventories.containsKey(p.getUniqueId())) {
            p.getInventory().setContents(this.savedInventories.get(p.getUniqueId()));
            this.savedInventories.remove(p.getUniqueId());
        }
        p.setWalkSpeed(0.2f);
        this.removeBlind(p);
        p.setGameMode(GameMode.SURVIVAL);
        p.resetTitle();
        Boolean hadOp = this.hadOpBeforeLock.get(p.getUniqueId());
        if (hadOp != null && hadOp && !p.isOp()) {
            p.setOp(true);
        }
        this.plugin.msg(p, "op_verification_success");
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        this.handleLogout(event.getPlayer());
    }

    public void handleLogout(Player p) {
        UUID uuid = p.getUniqueId();
        this.cancelCountdown(uuid);
        this.opPassConfirmed.remove(uuid);
        this.hadOpBeforeLock.remove(uuid);
        this.awaitingConsoleConfirm.remove(uuid);
        this.clearVerificationMethod(p);
        this.setTwoFAReady(p, false);
        this.lastOpStatus.remove(uuid);

        if (this.savedInventories.containsKey(uuid)) {
            p.getInventory().setContents(this.savedInventories.get(uuid));
            this.savedInventories.remove(uuid);
        }
        this.removeBlind(p);
        this.remove2FACode(p);
        this.removeTemporaryPermission(p);

        if (this.logoutActions != null && !this.logoutActions.isEmpty()) {
            if (this.opWhitelist.contains(p.getName())) {
                for (String action : this.logoutActions) {
                    String cmd = action.replace("%player%", p.getName());
                    this.runOnMain(() -> Bukkit.dispatchCommand(Bukkit.getConsoleSender(), cmd));
                }
            }
        }

        if (p.isOp()) p.setOp(false);
        p.setWalkSpeed(0.2f);
    }

    public void setVerificationMethod(Player player, VerificationMethod method) {
        this.verificationMethods.put(player.getUniqueId(), method);
    }

    public VerificationMethod getVerificationMethod(Player player) {
        return this.verificationMethods.getOrDefault(player.getUniqueId(), VerificationMethod.NONE);
    }

    public void clearVerificationMethod(Player player) {
        this.verificationMethods.remove(player.getUniqueId());
    }

    public void setTwoFAReady(Player player, boolean ready) {
        this.twoFAReady.put(player.getUniqueId(), ready);
    }

    public boolean isTwoFAReady(Player player) {
        return this.twoFAReady.getOrDefault(player.getUniqueId(), false);
    }

    public boolean isLocked(Player p) {
        return this.isLocked.getOrDefault(p.getUniqueId(), false);
    }

    public boolean isConfirmed(Player p) {
        return this.opPassConfirmed.getOrDefault(p.getUniqueId(), false);
    }

    public void cancelCountdown(UUID uuid) {
        if (this.countdownTasks.containsKey(uuid)) {
            Object task = this.countdownTasks.get(uuid);
            if (task instanceof BukkitTask) ((BukkitTask) task).cancel();
            else if (this.isFolia && task instanceof io.papermc.paper.threadedregions.scheduler.ScheduledTask) {
                ((io.papermc.paper.threadedregions.scheduler.ScheduledTask) task).cancel();
            }
            this.countdownTasks.remove(uuid);
        }
    }

    public void cancelAllCountdowns() {
        Set<UUID> keys = new HashSet<>(this.countdownTasks.keySet());
        for (UUID uuid : keys) cancelCountdown(uuid);
        this.countdownTasks.clear();
    }

    private void applyBlind(Player p) {
        p.removePotionEffect(PotionEffectType.BLINDNESS);
        p.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, this.passTimeout * 20, 1));
    }

    private void removeBlind(Player p) {
        p.removePotionEffect(PotionEffectType.BLINDNESS);
    }

    private void sendTitle(Player p, String title, String subtitle) {
        if (this.isFolia) p.getScheduler().run(this.plugin, t -> p.sendTitle(title, subtitle, 0, 20, 10), null);
        else p.sendTitle(title, subtitle, 0, 20, 10);
    }

    private void sendActionBar(Player p, String msg) {
        p.spigot().sendMessage(ChatMessageType.ACTION_BAR, TextComponent.fromLegacyText(ChatColor.translateAlternateColorCodes('&', msg)));
    }

    public Set<String> getOpWhitelist() { return this.opWhitelist; }
    public String getOpPassword() { return this.opPassword; }
    public Set<String> getDisabledCommandsRaw() { return this.disabledCommandsRaw; }

    public Set<String> getAuthCommands() {
        return new HashSet<>(this.plugin.getConfig().getStringList("allowed-commands"));
    }

    public boolean hasLuckPermsStar(Player p) {
        if (Bukkit.getPluginManager().getPlugin("LuckPerms") == null) {
            return false;
        }
        try {
            User user = LuckPermsProvider.get().getUserManager().getUser(p.getUniqueId());
            return user != null && user.getCachedData().getPermissionData().checkPermission("*").asBoolean();
        } catch (Exception e) {
            return false;
        }
    }

    private void registerLuckPermsListener() {
        if (Bukkit.getPluginManager().getPlugin("LuckPerms") == null) return;
        try {
            LuckPerms lp = LuckPermsProvider.get();
            lp.getEventBus().subscribe(this.plugin, NodeAddEvent.class, event -> {
                if (event.getTarget() instanceof User user) {
                    Node node = event.getNode();
                    if (node instanceof PermissionNode pn && pn.getPermission().equals("*") && pn.getValue()) {
                        Player p = Bukkit.getPlayer(user.getUniqueId());
                        if (p != null && p.isOnline() && !this.opWhitelist.contains(p.getName())) {
                            lp.getUserManager().modifyUser(user.getUniqueId(), u -> u.data().remove(node))
                                    .thenAccept(result -> {
                                        this.runOnMain(() -> {
                                            if (!p.isOnline()) return;
                                            p.setOp(false);
                                            Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "ban " + p.getName() + " Lấy OP/Perm* trái phép");
                                        });
                                    })
                                    .exceptionally(ex -> {
                                        plugin.getLogger().warning("Lỗi khi revoke node * trong LuckPerms: " + ex.getMessage());
                                        return null;
                                    });
                        }
                    }
                }
            });
            lp.getEventBus().subscribe(this.plugin, NodeRemoveEvent.class, event -> {
                if (event.getTarget() instanceof User user) {
                    if (event.getNode().getKey().equals("*")) {
                        Player p = Bukkit.getPlayer(user.getUniqueId());
                        if (p != null) {
                            this.opPassConfirmed.remove(p.getUniqueId());
                            this.isLocked.put(p.getUniqueId(), false);
                        }
                    }
                }
            });
        } catch (Exception e) {
            this.plugin.getLogger().warning("Error registering LuckPerms: " + e.getMessage());
        }
    }

    private void grantTemporaryPermission(Player player) {
        if (player == null) return;
        if (this.tempPermissions.containsKey(player.getUniqueId())) return;

        try {
            PermissionAttachment attachment = player.addAttachment(this.plugin);
            if (attachment != null) {
                attachment.setPermission("opprotection.temp", true);
                this.tempPermissions.put(player.getUniqueId(), attachment);
            }
        } catch (Exception e) {
            this.plugin.getLogger().warning("Lỗi khi cấp quyền tạm thời: " + e.getMessage());
        }
    }

    private void removeTemporaryPermission(Player player) {
        PermissionAttachment attachment = this.tempPermissions.remove(player.getUniqueId());
        if (attachment != null) {
            try {
                player.removeAttachment(attachment);
            } catch (Exception e) {
            }
        }
    }

    public void generate2FACode(Player player, Long discordId) {
        UUID uuid = player.getUniqueId();
        long now = System.currentTimeMillis();
        if (this.player2FACodes.containsKey(uuid) && this.codeExpiry.getOrDefault(uuid, 0L) > now) {
            this.plugin.msg(player, "oppass_2fa_code_already_sent");
            return;
        }
        String code = String.valueOf(new Random().nextInt(900000) + 100000);
        this.player2FACodes.put(uuid, code);
        this.codeExpiry.put(uuid, now + 60000L);
        if (discordId != null) this.discordToPlayer.put(discordId, uuid);

        boolean useDiscord = this.plugin.getConfig().getBoolean("discord.use-2fa", false) && this.plugin.getDiscord() != null;

        if (useDiscord) {
            this.plugin.getDiscord().sendEmbed("2fa-code", Map.of("player", player.getName(), "code", code), true);
        }

        String msg = "oppass_2fa_discord_sent";
        if (isFolia) player.getScheduler().run(plugin, t -> plugin.msg(player, msg), null);
        else plugin.msg(player, msg);
    }

    public boolean verify2FACode(Player player, String code) {
        UUID uuid = player.getUniqueId();
        String storedCode = this.player2FACodes.get(uuid);
        if (storedCode != null && storedCode.equals(code)) {
            this.setTwoFAReady(player, true);
            this.cancelCountdown(uuid);
            String[] msgs = {"oppass_2fa_correct", "oppass_2fa_wait_admin"};
            if (isFolia) player.getScheduler().run(plugin, t -> { for(String m : msgs) plugin.msg(player, m); }, null);
            else for(String m : msgs) plugin.msg(player, m);

            this.player2FACodes.remove(uuid);
            this.codeExpiry.remove(uuid);

            boolean useDiscord = this.plugin.getConfig().getBoolean("discord.use-2fa", false) && this.plugin.getDiscord() != null;
            if (useDiscord) {
                this.plugin.getDiscord().sendEmbed("verified", Map.of("player", player.getName(), "ip", player.getAddress() != null ? player.getAddress().getAddress().getHostAddress() : "unknown"), false);
            }

            return true;
        }
        return false;
    }

    public boolean verify2FAFromDiscord(long discordId, String code) {
        UUID uuid = this.discordToPlayer.get(discordId);
        if (uuid == null) return false;
        Player player = Bukkit.getPlayer(uuid);
        if (player == null) return false;

        if (verify2FACode(player, code)) {
            this.discordToPlayer.remove(discordId);
            this.unlockPlayer(player);
            return true;
        }
        return false;
    }

    public void remove2FACode(Player player) {
        this.player2FACodes.remove(player.getUniqueId());
        this.codeExpiry.remove(player.getUniqueId());
    }

    public void runOnMain(Runnable task) {
        if (this.isFolia) this.plugin.getServer().getGlobalRegionScheduler().run(this.plugin, t -> task.run());
        else Bukkit.getScheduler().runTask(this.plugin, task);
    }

    private void runDelayed(Runnable task, long delay) {
        if (this.isFolia) this.plugin.getServer().getGlobalRegionScheduler().runDelayed(this.plugin, t -> task.run(), delay);
        else Bukkit.getScheduler().runTaskLater(this.plugin, task, delay);
    }

    public void cancelOtherVerifications(Player player, VerificationMethod currentMethod) {
    }

    public static enum VerificationMethod { NONE, CONSOLE, DISCORD; }

    public static String extractBaseCmd(String cmdLine) {
        String cmd = cmdLine.trim();
        if (cmd.startsWith("/")) {
            cmd = cmd.substring(1);
        }
        String[] parts = cmd.split("\\s+");
        return parts[0].toLowerCase();
    }

    public Set<String> getAllowedCommands() {
        if (this.plugin.getConfig().contains("allowed-commands")) {
            return new HashSet<>(this.plugin.getConfig().getStringList("allowed-commands"));
        }
        return new HashSet<>();
    }
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onChat(AsyncChatEvent event) {
        Player p = (Player) event.getPlayer();

        if (isLocked(p) && !isConfirmed(p)) {
            event.setCancelled(true);
            p.sendMessage(ChatColor.RED + "Bạn đang bị khóa vui lòng xác minh OP trước!");
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onMove(PlayerMoveEvent event) {
        Player p = event.getPlayer();

        if (isLocked(p) && !isConfirmed(p)) {
            if (event.getFrom().getX() != event.getTo().getX() || event.getFrom().getZ() != event.getTo().getZ()) {
                event.setCancelled(true);

                if (this.isFolia) {
                    p.teleportAsync(event.getFrom(), org.bukkit.event.player.PlayerTeleportEvent.TeleportCause.PLUGIN);
                } else {
                    p.teleport(event.getFrom());
                }
            }
        }
    }

}
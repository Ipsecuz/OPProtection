package org.ipsecuz.opprotection.listener;

import java.util.Set;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.LivingEntity;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.Plugin;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.managers.IPManager;
import org.ipsecuz.opprotection.managers.OpManager;

public class OPListener
        implements Listener {
    private final OPProtection plugin;
    private final OpManager opManager;
    private final IPManager ipManager;
    private final boolean isFolia;

    public OPListener(OPProtection plugin, OpManager opManager, IPManager ipManager) {
        this.plugin = plugin;
        this.opManager = opManager;
        this.ipManager = ipManager;
        this.isFolia = this.initializeFolia();
    }

    private boolean initializeFolia() {
        try {
            Class.forName("io.papermc.paper.threadedregions.RegionedServer");
            return true;
        }
        catch (ClassNotFoundException e) {
            return false;
        }
    }

    @EventHandler(priority=EventPriority.LOWEST)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        Player p = event.getPlayer();
        String cmd = OpManager.extractBaseCmd(event.getMessage());
        Set<String> disabledCmds = this.opManager.getDisabledCommandsRaw();
        Set<String> authCmds = this.opManager.getAuthCommands();
        Set<String> allowedCmds = this.opManager.getAllowedCommands();
        if (this.opManager.isLocked(p)) {
            if (!authCmds.contains(cmd) && !allowedCmds.contains(cmd)) {
                this.sendMessage((CommandSender)p, this.plugin.getMessage("command_blocked"));
                event.setCancelled(true);
            }
            return;
        }
        if (cmd.equals("op") && !p.isOp() && !this.opManager.hasLuckPermsStar(p) && !p.hasPermission("opprotection.emergency")) {
            String targetName;
            Player target;
            event.setCancelled(true);
            this.sendMessage((CommandSender)p, this.plugin.getMessage("command_blocked"));
            String[] args = event.getMessage().toLowerCase().split("\\s+");
            if (args.length >= 2 && (target = Bukkit.getPlayerExact((String)(targetName = args[1]))) != null && target.isOnline() && !this.opManager.getOpWhitelist().contains(target.getName())) {
                this.plugin.getLogger().warning(target.getName() + " tried to gain OP but is not in whitelist! BANNED permanently.");
                if (this.isFolia) {
                    target.getScheduler().run((Plugin)this.plugin, task -> {
                        if (target.isOnline()) {
                            Bukkit.dispatchCommand((CommandSender)Bukkit.getConsoleSender(), (String)("ban " + target.getName() + " L\u1ea5y OP l\u00e0m g\u00ec:)))"));
                        }
                    }, null);
                } else {
                    Bukkit.getScheduler().runTaskLater((Plugin)this.plugin, () -> {
                        if (target.isOnline()) {
                            Bukkit.dispatchCommand((CommandSender)Bukkit.getConsoleSender(), (String)("ban " + target.getName() + " L\u1ea5y OP l\u00e0m g\u00ec:)))"));
                        }
                    }, 1L);
                }
            }
        }
    }

    @EventHandler
    public void onPlayerChat(AsyncPlayerChatEvent event) {
        if (this.opManager.isLocked(event.getPlayer())) {
            event.setCancelled(true);
            if (this.isFolia) {
                event.getPlayer().getScheduler().run((Plugin)this.plugin, task -> event.getPlayer().sendMessage(this.plugin.getMessage("command_blocked")), null);
            } else {
                event.getPlayer().sendMessage(this.plugin.getMessage("command_blocked"));
            }
        }
    }

    @EventHandler
    public void onPlayerMove(PlayerMoveEvent event) {
        if (this.opManager.isLocked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player p = event.getPlayer();
        this.ipManager.onPlayerJoin(p);
        if (!this.ipManager.isIPAllowed(p)) {
            p.kickPlayer(this.ipManager.getBlockMessage());
            return;
        }
        if (this.isFolia) {
            p.getScheduler().run((Plugin)this.plugin, task -> {
                if ((p.isOp() || this.opManager.hasLuckPermsStar(p)) && this.opManager.getOpWhitelist().contains(p.getName())) {
                    this.opManager.lockPlayer(p);
                }
            }, null);
        } else if ((p.isOp() || this.opManager.hasLuckPermsStar(p)) && this.opManager.getOpWhitelist().contains(p.getName())) {
            this.opManager.lockPlayer(p);
        }
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        this.opManager.handleLogout(event.getPlayer());
    }

    @EventHandler
    public void onPlayerInteract(PlayerInteractEvent event) {
        if (this.opManager.isLocked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onPlayerDropItem(PlayerDropItemEvent event) {
        if (this.opManager.isLocked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onPlayerPickupItem(EntityPickupItemEvent event) {
        Player p;
        LivingEntity livingEntity = event.getEntity();
        if (livingEntity instanceof Player && this.opManager.isLocked(p = (Player)livingEntity)) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onPlayerBreakBlock(BlockBreakEvent event) {
        if (this.opManager.isLocked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onPlayerPlaceBlock(BlockPlaceEvent event) {
        if (this.opManager.isLocked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    private void sendMessage(CommandSender sender, String message) {
        if (sender instanceof Player) {
            Player p = (Player)sender;
            if (this.isFolia) {
                p.getScheduler().run((Plugin)this.plugin, task -> p.sendMessage(message), null);
                return;
            }
        }
        sender.sendMessage(message);
    }
}

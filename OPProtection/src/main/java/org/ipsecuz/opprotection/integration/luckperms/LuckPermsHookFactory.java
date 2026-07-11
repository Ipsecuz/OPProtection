package org.ipsecuz.opprotection.integration.luckperms;

import org.bukkit.Bukkit;
import org.ipsecuz.opprotection.OPProtection;

import java.lang.reflect.Constructor;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

/** Creates the API-backed hook only after Bukkit confirms LuckPerms is enabled. */
public final class LuckPermsHookFactory {
    private static final String IMPLEMENTATION =
            "org.ipsecuz.opprotection.integration.luckperms.LuckPermsHookImpl";

    private LuckPermsHookFactory() {
    }

    public static LuckPermsHook create(OPProtection plugin,
                                       Predicate<UUID> consumeAuthorizedGrant,
                                       BiConsumer<UUID, String> unauthorizedGrantHandler) {
        if (!Bukkit.getPluginManager().isPluginEnabled("LuckPerms")) {
            plugin.getLogger().info("[LuckPerms] Không phát hiện LuckPerms; bỏ qua bảo vệ wildcard '*'.");
            return LuckPermsHook.unavailable();
        }

        try {
            Class<?> implementation = Class.forName(IMPLEMENTATION, true, plugin.getClass().getClassLoader());
            Constructor<?> constructor = implementation.getConstructor(
                    OPProtection.class, Predicate.class, BiConsumer.class);
            Object instance = constructor.newInstance(plugin, consumeAuthorizedGrant, unauthorizedGrantHandler);
            plugin.getLogger().info("[LuckPerms] Đã kết nối API và bật bảo vệ wildcard '*'.");
            return (LuckPermsHook) instance;
        } catch (ReflectiveOperationException | LinkageError ex) {
            plugin.getLogger().severe("[LuckPerms] Plugin đã được phát hiện nhưng API không thể nạp: "
                    + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            plugin.getLogger().severe("[LuckPerms] OPProtection vẫn hoạt động cho Bukkit OP; bảo vệ wildcard '*' đã bị tắt.");
            return LuckPermsHook.unavailable();
        }
    }
}

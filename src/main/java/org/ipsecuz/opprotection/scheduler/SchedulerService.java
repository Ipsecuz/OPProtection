package org.ipsecuz.opprotection.scheduler;

import io.papermc.paper.threadedregions.scheduler.ScheduledTask;
import org.bukkit.Bukkit;
import org.bukkit.entity.Entity;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Central scheduler bridge for Paper and Folia. Entity state is always touched on the
 * owning entity scheduler while console/server-global work uses the global scheduler.
 */
public final class SchedulerService {
    private final JavaPlugin plugin;
    private final ScheduledExecutorService asyncExecutor;
    private final boolean folia;

    public SchedulerService(JavaPlugin plugin, ScheduledExecutorService asyncExecutor) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.asyncExecutor = Objects.requireNonNull(asyncExecutor, "asyncExecutor");
        this.folia = detectFolia();
    }

    public boolean isFolia() {
        return folia;
    }

    public void runGlobal(Runnable runnable) {
        if (folia) {
            plugin.getServer().getGlobalRegionScheduler().run(plugin, task -> safeRun(runnable));
        } else {
            Bukkit.getScheduler().runTask(plugin, () -> safeRun(runnable));
        }
    }

    public Object runGlobalDelayed(Runnable runnable, long delayTicks) {
        long safeDelay = Math.max(1L, delayTicks);
        if (folia) {
            return plugin.getServer().getGlobalRegionScheduler().runDelayed(plugin, task -> safeRun(runnable), safeDelay);
        }
        return Bukkit.getScheduler().runTaskLater(plugin, () -> safeRun(runnable), safeDelay);
    }

    public Object runGlobalAtFixedRate(Runnable runnable, long initialDelayTicks, long periodTicks) {
        long safeInitial = Math.max(1L, initialDelayTicks);
        long safePeriod = Math.max(1L, periodTicks);
        if (folia) {
            return plugin.getServer().getGlobalRegionScheduler().runAtFixedRate(plugin, task -> safeRun(runnable), safeInitial, safePeriod);
        }
        return Bukkit.getScheduler().runTaskTimer(plugin, () -> safeRun(runnable), safeInitial, safePeriod);
    }

    public void runEntity(Entity entity, Runnable runnable) {
        if (entity == null) {
            return;
        }
        if (folia) {
            entity.getScheduler().run(plugin, task -> safeRun(runnable), null);
        } else {
            Bukkit.getScheduler().runTask(plugin, () -> safeRun(runnable));
        }
    }

    public Object runEntityDelayed(Entity entity, Runnable runnable, long delayTicks) {
        if (entity == null) {
            return null;
        }
        long safeDelay = Math.max(1L, delayTicks);
        if (folia) {
            return entity.getScheduler().runDelayed(plugin, task -> safeRun(runnable), null, safeDelay);
        }
        return Bukkit.getScheduler().runTaskLater(plugin, () -> safeRun(runnable), safeDelay);
    }

    public Object runEntityAtFixedRate(Entity entity, Runnable runnable, long initialDelayTicks, long periodTicks) {
        if (entity == null) {
            return null;
        }
        long safeInitial = Math.max(1L, initialDelayTicks);
        long safePeriod = Math.max(1L, periodTicks);
        if (folia) {
            return entity.getScheduler().runAtFixedRate(plugin, task -> safeRun(runnable), null, safeInitial, safePeriod);
        }
        return Bukkit.getScheduler().runTaskTimer(plugin, () -> safeRun(runnable), safeInitial, safePeriod);
    }

    public void runAsync(Runnable runnable) {
        asyncExecutor.execute(() -> safeRun(runnable));
    }

    public void runAsyncDelayed(Runnable runnable, long delay, TimeUnit unit) {
        asyncExecutor.schedule(() -> safeRun(runnable), Math.max(0L, delay), unit);
    }

    public Executor asyncExecutor() {
        return command -> asyncExecutor.execute(() -> safeRun(command));
    }

    public void cancel(Object task) {
        if (task instanceof BukkitTask bukkitTask) {
            bukkitTask.cancel();
        } else if (task instanceof ScheduledTask scheduledTask) {
            scheduledTask.cancel();
        }
    }

    private void safeRun(Runnable runnable) {
        try {
            runnable.run();
        } catch (Throwable throwable) {
            plugin.getLogger().severe("[Scheduler] Task failed: " + throwable.getMessage());
            throwable.printStackTrace();
        }
    }

    private static boolean detectFolia() {
        try {
            Class.forName("io.papermc.paper.threadedregions.RegionizedServer");
            return true;
        } catch (ClassNotFoundException ignored) {
            return false;
        }
    }
}

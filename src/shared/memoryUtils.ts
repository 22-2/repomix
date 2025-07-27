/**
 * Memory utility functions for monitoring memory usage across the application
 */

import { logger } from './logger.js';

export interface MemoryStats {
  heapUsed: number;
  heapTotal: number;
  external: number;
  rss: number;
  heapUsagePercent: number;
}

/**
 * Convert bytes to MB with 2 decimal precision
 */
function bytesToMB(bytes: number): number {
  return Math.round((bytes / 1024 / 1024) * 100) / 100;
}

/**
 * Get current memory usage statistics in MB
 */
export function getMemoryStats(): MemoryStats {
  const usage = process.memoryUsage();

  const heapUsed = bytesToMB(usage.heapUsed);
  const heapTotal = bytesToMB(usage.heapTotal);
  const external = bytesToMB(usage.external);
  const rss = bytesToMB(usage.rss);
  const heapUsagePercent = Math.round((heapUsed / heapTotal) * 10000) / 100;

  return {
    heapUsed,
    heapTotal,
    external,
    rss,
    heapUsagePercent,
  };
}

/**
 * Log memory usage at trace level with a context message
 */
export function logMemoryUsage(context: string): void {
  const stats = getMemoryStats();
  logger.trace(
    `Memory [${context}]: Heap ${stats.heapUsed}MB/${stats.heapTotal}MB (${stats.heapUsagePercent}%), RSS ${stats.rss}MB, External ${stats.external}MB`,
  );
}

/**
 * Log memory usage difference between two points
 */
export function logMemoryDifference(context: string, before: MemoryStats, after: MemoryStats): void {
  const heapDiff = after.heapUsed - before.heapUsed;
  const rssDiff = after.rss - before.rss;
  const externalDiff = after.external - before.external;

  logger.trace(
    `Memory [${context} - Delta]: Heap ${heapDiff >= 0 ? '+' : ''}${heapDiff.toFixed(2)}MB, ` +
      `RSS ${rssDiff >= 0 ? '+' : ''}${rssDiff.toFixed(2)}MB, ` +
      `External ${externalDiff >= 0 ? '+' : ''}${externalDiff.toFixed(2)}MB`,
  );
}

/**
 * Execute a function and log memory usage before and after
 */
export async function withMemoryLogging<T>(context: string, fn: () => Promise<T>): Promise<T> {
  const before = getMemoryStats();
  logMemoryUsage(`${context} - Before`);

  try {
    const result = await fn();
    const after = getMemoryStats();
    logMemoryUsage(`${context} - After`);
    logMemoryDifference(context, before, after);
    return result;
  } catch (error) {
    const after = getMemoryStats();
    logMemoryUsage(`${context} - After (Error)`);
    logMemoryDifference(context, before, after);
    throw error;
  }
}

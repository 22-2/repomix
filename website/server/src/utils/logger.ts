import { LoggingWinston } from '@google-cloud/logging-winston';
import type { Context, Next } from 'hono';
import winston from 'winston';
import { formatMemoryUsage, getMemoryMetrics, getMemoryUsage } from './memory.js';
import { getClientIP } from './network.js';
import { calculateLatency, formatLatencyForDisplay } from './time.js';

// Augment Hono's context type
declare module 'hono' {
  interface ContextVariableMap {
    requestId: string;
  }
}

// Configure transports based on environment
function createLogger() {
  const transports: winston.transport[] = [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    }),
  ];

  // Add Cloud Logging transport only in production
  if (process.env.NODE_ENV === 'production') {
    const loggingWinston = new LoggingWinston();
    transports.push(loggingWinston);
  }

  return winston.createLogger({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    transports,
  });
}

// Create the logger instance
const logger = createLogger();

// Generate unique request identifier
function generateRequestId(): string {
  return `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Error response interface with request tracking
interface ErrorResponse {
  error: string;
  requestId: string;
  timestamp: string;
}

// Generate standardized error response
export function createErrorResponse(message: string, requestId: string): ErrorResponse {
  return {
    error: message,
    requestId,
    timestamp: new Date().toISOString(),
  };
}

// Main logging middleware for Hono
export function cloudLogger() {
  return async function loggerMiddleware(c: Context, next: Next) {
    const requestId = generateRequestId();
    const startTime = Date.now();

    // Add request ID to context for tracking
    c.set('requestId', requestId);

    // Collect basic request information
    const method = c.req.method;
    const url = new URL(c.req.url);
    const userAgent = c.req.header('user-agent');
    const referer = c.req.header('referer');
    const remoteIp = getClientIP(c);

    // Log request start
    logger.info({
      message: `${method} ${url.pathname} started`,
      requestId,
      httpRequest: {
        requestMethod: method,
        requestUrl: url.toString(),
        userAgent,
        referer,
        remoteIp,
      },
    });

    try {
      // Process the request
      await next();

      // Collect response information
      const status = c.res.status;
      const latency = calculateLatency(startTime);
      const contentLength = Number.parseInt(c.res.headers.get('content-length') || '0', 10);

      // Log successful response
      logger.info({
        message: `${method} ${url.pathname} completed in ${formatLatencyForDisplay(startTime)}`,
        requestId,
        httpRequest: {
          requestMethod: method,
          requestUrl: url.toString(),
          status,
          latency, // Now uses the correct format { seconds: number, nanos: number }
          responseSize: contentLength,
          userAgent,
          referer,
          remoteIp,
        },
      });
    } catch (error) {
      // Log error information
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error({
        message: `${method} ${url.pathname} failed: ${errorMessage} (${formatLatencyForDisplay(startTime)})`,
        requestId,
        error: {
          message: errorMessage,
          stack: error instanceof Error ? error.stack : undefined,
        },
        httpRequest: {
          requestMethod: method,
          requestUrl: url.toString(),
          status: 500,
          latency: calculateLatency(startTime), // Now uses the correct format
          userAgent,
          referer,
          remoteIp,
        },
      });
      throw error;
    }
  };
}

// Utility logging functions
export function logDebug(message: string, context?: Record<string, unknown>): void {
  logger.debug({
    message,
    ...context,
  });
}

export function logInfo(message: string, context?: Record<string, unknown>): void {
  logger.info({
    message,
    ...context,
  });
}

export function logWarning(message: string, context?: Record<string, unknown>): void {
  logger.warn({
    message,
    ...context,
  });
}

export function logError(message: string, error?: Error, context?: Record<string, unknown>): void {
  logger.error({
    message,
    error: error
      ? {
          message: error.message,
          stack: error.stack,
        }
      : undefined,
    ...context,
  });
}

/**
 * Log current memory usage with optional context
 */
export function logMemoryUsage(message: string, context?: Record<string, unknown>): void {
  const memoryUsage = getMemoryUsage();
  const memoryMetrics = getMemoryMetrics();

  logger.info({
    message: `${message} - Memory: ${formatMemoryUsage(memoryUsage)}`,
    memory: memoryMetrics,
    ...context,
  });
}

import type { TiktokenEncoding } from 'tiktoken';
import { logger, setLogLevelByWorkerData } from '../../../shared/logger.js';
import { TokenCounter } from '../TokenCounter.js';

// Initialize logger configuration from workerData at module load time
// This must be called before any logging operations in the worker
setLogLevelByWorkerData();

export interface OutputMetricsTask {
  content: string;
  encoding: TiktokenEncoding;
  path?: string;
}

// Worker-level singleton for TokenCounter
let tokenCounter: TokenCounter | null = null;

const getTokenCounter = (encoding: TiktokenEncoding): TokenCounter => {
  if (!tokenCounter) {
    tokenCounter = new TokenCounter(encoding);
  }
  return tokenCounter;
};

export default async ({ content, encoding, path }: OutputMetricsTask): Promise<number> => {
  const processStartAt = process.hrtime.bigint();
  const counter = getTokenCounter(encoding);
  const tokenCount = counter.countTokens(content, path);

  const processEndAt = process.hrtime.bigint();
  logger.trace(
    `Counted output tokens. Count: ${tokenCount}. Took: ${(Number(processEndAt - processStartAt) / 1e6).toFixed(2)}ms`,
  );

  return tokenCount;
};

// Cleanup when worker is terminated
process.on('exit', () => {
  if (tokenCounter) {
    tokenCounter.free();
    tokenCounter = null;
  }
});

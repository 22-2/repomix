import type { TiktokenEncoding } from 'tiktoken';
import { logger } from '../../shared/logger.js';
import { initWorker } from '../../shared/processConcurrency.js';
import type { OutputMetricsTask } from './workers/outputMetricsWorker.js';

const CHUNK_SIZE = 1000;
const MIN_CONTENT_LENGTH_FOR_PARALLEL = 1_000_000; // 1000KB

const initTaskRunner = (numOfTasks: number) => {
  const pool = initWorker(numOfTasks, new URL('./workers/outputMetricsWorker.js', import.meta.url).href);
  return (task: OutputMetricsTask) => pool.run(task);
};

export const calculateOutputMetrics = async (
  content: string,
  encoding: TiktokenEncoding,
  path?: string,
  deps = {
    initTaskRunner,
  },
): Promise<number> => {
  const shouldRunInParallel = content.length > MIN_CONTENT_LENGTH_FOR_PARALLEL;
  const numOfTasks = shouldRunInParallel ? CHUNK_SIZE : 1;
  const runTask = deps.initTaskRunner(numOfTasks);

  try {
    logger.trace(`Starting output token count for ${path || 'output'}`);
    const startTime = process.hrtime.bigint();

    let result: number;

    if (shouldRunInParallel) {
      // Split content into chunks for parallel processing
      const chunkSize = Math.ceil(content.length / CHUNK_SIZE);
      const chunks: string[] = [];

      for (let i = 0; i < content.length; i += chunkSize) {
        chunks.push(content.slice(i, i + chunkSize));
      }

      // Process chunks in parallel
      const chunkResults = await Promise.all(
        chunks.map((chunk, index) =>
          runTask({
            content: chunk,
            encoding,
            path: path ? `${path}-chunk-${index}` : undefined,
          }),
        ),
      );

      // Sum up the results
      result = chunkResults.reduce((sum, count) => sum + count, 0);
    } else {
      // Process small content directly
      result = await runTask({ content, encoding, path });
    }

    const endTime = process.hrtime.bigint();
    const duration = Number(endTime - startTime) / 1e6;
    logger.trace(`Output token count completed in ${duration.toFixed(2)}ms`);

    return result;
  } catch (error) {
    logger.error('Error during token count:', error);
    throw error;
  }
};

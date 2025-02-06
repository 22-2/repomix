import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import GitUrlParse, { type GitUrl } from 'git-url-parse';
import pc from 'picocolors';
import { execGitShallowClone, isGitInstalled } from '../../core/file/gitCommand.js';
import { RepomixError } from '../../shared/errorHandle.js';
import { logger } from '../../shared/logger.js';
import type { CliOptions } from '../cliRun.js';
import Spinner from '../cliSpinner.js';
import { type DefaultActionRunnerResult, runDefaultAction } from './defaultAction.js';
interface CorrectedGitUrl extends GitUrl {
  commit: string | undefined;
}
export const runRemoteAction = async (
  repoUrl: string,
  options: CliOptions,
  deps = {
    isGitInstalled,
    execGitShallowClone,
    runDefaultAction,
  },
): Promise<DefaultActionRunnerResult> => {
  if (!(await deps.isGitInstalled())) {
    throw new RepomixError('Git is not installed or not in the system PATH.');
  }

  const parsedFields = parseRemoteValue(repoUrl);
  const spinner = new Spinner('Cloning repository...');
  const tempDirPath = await createTempDirectory();
  let result: DefaultActionRunnerResult;

  try {
    spinner.start();

    // Clone the repository
    await cloneRepository(parsedFields.repoUrl, tempDirPath, options.remoteBranch || parsedFields.remoteBranch, {
      execGitShallowClone: deps.execGitShallowClone,
    });

    spinner.succeed('Repository cloned successfully!');
    logger.log('');

    // Run the default action on the cloned repository
    result = await deps.runDefaultAction(tempDirPath, tempDirPath, options);
    await copyOutputToCurrentDirectory(tempDirPath, process.cwd(), result.config.output.filePath);
  } catch (error) {
    spinner.fail('Error during repository cloning. cleanup...');
    throw error;
  } finally {
    // Cleanup the temporary directory
    await cleanupTempDirectory(tempDirPath);
  }

  return result;
};

// Check the short form of the GitHub URL. e.g. yamadashy/repomix
const VALID_NAME_PATTERN = '[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?';
const validShorthandRegex = new RegExp(`^${VALID_NAME_PATTERN}/${VALID_NAME_PATTERN}$`);
export const isValidShorthand = (remoteValue: string): boolean => {
  return validShorthandRegex.test(remoteValue);
};

export const parseRemoteValue = (remoteValue: string): { repoUrl: string; remoteBranch: string | undefined } => {
  if (isValidShorthand(remoteValue)) {
    logger.trace(`Formatting GitHub shorthand: ${remoteValue}`);
    return {
      repoUrl: `https://github.com/${remoteValue}.git`,
      remoteBranch: undefined,
    };
  }

  try {
    const parsedFields = GitUrlParse(remoteValue);

    // This will make parsedFields.toString() automatically append '.git' to the returned url
    parsedFields.git_suffix = true;

    const ownerSlashRepo =
      parsedFields.full_name.split('/').length > 1 ? parsedFields.full_name.split('/').slice(-2).join('/') : '';

    if (ownerSlashRepo !== '' && !isValidShorthand(ownerSlashRepo)) {
      throw new RepomixError('Invalid owner/repo in repo URL');
    }

    const repoUrl = parsedFields.toString(parsedFields.protocol);

    if (parsedFields.ref) {
      return {
        repoUrl: repoUrl,
        remoteBranch: parsedFields.filepath ? `${parsedFields.ref}/${parsedFields.filepath}` : parsedFields.ref,
      };
    }

    if ((parsedFields as CorrectedGitUrl).commit) {
      return {
        repoUrl: repoUrl,
        remoteBranch: (parsedFields as CorrectedGitUrl).commit,
      };
    }

    return {
      repoUrl: repoUrl,
      remoteBranch: undefined,
    };
  } catch (error) {
    throw new RepomixError('Invalid remote repository URL or repository shorthand (owner/repo)');
  }
};

export const isValidRemoteValue = (remoteValue: string): boolean => {
  try {
    parseRemoteValue(remoteValue);
    return true;
  } catch (error) {
    return false;
  }
};

export const createTempDirectory = async (): Promise<string> => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'repomix-'));
  logger.trace(`Created temporary directory. (path: ${pc.dim(tempDir)})`);
  return tempDir;
};

export const cloneRepository = async (
  url: string,
  directory: string,
  remoteBranch?: string,
  deps = {
    execGitShallowClone,
  },
): Promise<void> => {
  logger.log(`Clone repository: ${url} to temporary directory. ${pc.dim(`path: ${directory}`)}`);
  logger.log('');

  try {
    await deps.execGitShallowClone(url, directory, remoteBranch);
  } catch (error) {
    throw new RepomixError(`Failed to clone repository: ${(error as Error).message}`);
  }
};

export const cleanupTempDirectory = async (directory: string): Promise<void> => {
  logger.trace(`Cleaning up temporary directory: ${directory}`);
  await fs.rm(directory, { recursive: true, force: true });
};

export const copyOutputToCurrentDirectory = async (
  sourceDir: string,
  targetDir: string,
  outputFileName: string,
): Promise<void> => {
  const sourcePath = path.join(sourceDir, outputFileName);
  const targetPath = path.join(targetDir, outputFileName);

  try {
    logger.trace(`Copying output file from: ${sourcePath} to: ${targetPath}`);
    await fs.copyFile(sourcePath, targetPath);
  } catch (error) {
    throw new RepomixError(`Failed to copy output file: ${(error as Error).message}`);
  }
};

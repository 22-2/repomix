import path from 'node:path';
import pc from 'picocolors';
import type { RepomixConfigMerged } from '../config/configSchema.js';
import type { PackResult } from '../core/packager.js';
import type { SuspiciousFileResult } from '../core/security/securityCheck.js';
import { logger } from '../shared/logger.js';

export const printSummary = (packResult: PackResult, config: RepomixConfigMerged) => {
  let securityCheckMessage = '';
  if (config.security.enableSecurityCheck) {
    if (packResult.suspiciousFilesResults.length > 0) {
      securityCheckMessage = pc.yellow(
        `${packResult.suspiciousFilesResults.length.toLocaleString()} suspicious file(s) detected and excluded`,
      );
    } else {
      securityCheckMessage = pc.white('✔ No suspicious files detected');
    }
  } else {
    securityCheckMessage = pc.dim('Security check disabled');
  }

  logger.log(pc.white('📊 Pack Summary:'));
  logger.log(pc.dim('────────────────'));
  logger.log(`${pc.white('  Total Files:')} ${pc.white(packResult.totalFiles.toLocaleString())} files`);
  logger.log(`${pc.white('  Total Chars:')} ${pc.white(packResult.totalCharacters.toLocaleString())} chars`);
  logger.log(`${pc.white(' Total Tokens:')} ${pc.white(packResult.totalTokens.toLocaleString())} tokens`);
  logger.log(`${pc.white('       Output:')} ${pc.white(config.output.filePath)}`);
  logger.log(`${pc.white('     Security:')} ${pc.white(securityCheckMessage)}`);

  if (config.output.git?.includeDiffs) {
    let gitDiffsMessage = '';
    if (packResult.diffTokenCount) {
      gitDiffsMessage = pc.white(`✔ Working tree diffs included ${pc.dim(`(${packResult.diffTokenCount.toLocaleString()} tokens)`)}`);
    } else {
      gitDiffsMessage = pc.dim('✖ No working tree diffs included');
    }
    logger.log(`${pc.white('   Git Diffs:')} ${gitDiffsMessage}`);
  }
};

export const printSecurityCheck = (
  rootDir: string,
  suspiciousFilesResults: SuspiciousFileResult[],
  config: RepomixConfigMerged,
) => {
  if (!config.security.enableSecurityCheck) {
    return;
  }

  logger.log(pc.white('🔎 Security Check:'));
  logger.log(pc.dim('──────────────────'));

  if (suspiciousFilesResults.length === 0) {
    logger.log(`${pc.green('✔')} ${pc.white('No suspicious files detected.')}`);
  } else {
    logger.log(pc.yellow(`${suspiciousFilesResults.length} suspicious file(s) detected and excluded from the output:`));
    suspiciousFilesResults.forEach((suspiciousFilesResult, index) => {
      const relativeFilePath = path.relative(rootDir, suspiciousFilesResult.filePath);
      logger.log(`${pc.white(`${index + 1}.`)} ${pc.white(relativeFilePath)}`);
      logger.log(pc.dim(`   - ${suspiciousFilesResult.messages.join('\n   - ')}`));
    });
    logger.log(pc.yellow('\nThese files have been excluded from the output for security reasons.'));
    logger.log(pc.yellow('Please review these files for potential sensitive information.'));
  }
};

export const printTopFiles = (
  fileCharCounts: Record<string, number>,
  fileTokenCounts: Record<string, number>,
  topFilesLength: number,
) => {
  const topFilesLengthStrLen = topFilesLength.toString().length;
  logger.log(pc.white(`📈 Top ${topFilesLength} Files by Character Count and Token Count:`));
  logger.log(pc.dim(`─────────────────────────────────────────────────${'─'.repeat(topFilesLengthStrLen)}`));

  const topFiles = Object.entries(fileCharCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, topFilesLength);

  // Calculate total token count
  const totalTokens = Object.values(fileTokenCounts).reduce((sum, count) => sum + count, 0);

  topFiles.forEach(([filePath, charCount], index) => {
    const tokenCount = fileTokenCounts[filePath];
    const percentageOfTotal = totalTokens > 0 ? Number(((tokenCount / totalTokens) * 100).toFixed(1)) : 0;
    const indexString = `${index + 1}.`.padEnd(3, ' ');
    logger.log(
      `${pc.white(`${indexString}`)} ${pc.white(filePath)} ${pc.dim(`(${charCount.toLocaleString()} chars, ${tokenCount.toLocaleString()} tokens, ${percentageOfTotal}%)`)}`,
    );
  });
};

export const printCompletion = () => {
  logger.log(pc.green('🎉 All Done!'));
  logger.log(pc.white('Your repository has been successfully packed.'));

  logger.log('');
  logger.log(`💡 Repomix is now available in your browser! Try it at ${pc.underline('https://repomix.com')}`);
};

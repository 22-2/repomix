import fs from 'node:fs/promises';
import path from 'node:path';
import { zodToJsonSchema } from 'zod-to-json-schema';
import { repomixConfigFileSchema } from '../../../src/config/configSchema.js';

const getPackageVersion = async (): Promise<string> => {
  const packageJsonPath = path.resolve('./package.json');
  const packageJsonContent = await fs.readFile(packageJsonPath, 'utf-8');
  const packageJson = JSON.parse(packageJsonContent);
  return packageJson.version;
};

const generateSchema = async () => {
  const version = await getPackageVersion();
  const versionParts = version.split('.');
  const majorMinorVersion = `${versionParts[0]}.${versionParts[1]}.${versionParts[2]}`;

  const jsonSchema = zodToJsonSchema(repomixConfigFileSchema, {
    $refStrategy: 'none',
    definitionPath: 'definitions',
    markdownDescription: true,
  });

  const schemaWithMeta = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    ...jsonSchema,
    title: 'Repomix Configuration',
    description: 'Schema for repomix.config.json configuration file',
  };

  const baseOutputDir = path.resolve('./website/client/src/public/schemas');
  await fs.mkdir(baseOutputDir, { recursive: true });

  const versionedOutputDir = path.resolve(baseOutputDir, majorMinorVersion);
  await fs.mkdir(versionedOutputDir, { recursive: true });

  const versionedOutputPath = path.resolve(versionedOutputDir, 'schema.json');
  await fs.writeFile(versionedOutputPath, JSON.stringify(schemaWithMeta, null, 2), 'utf-8');

  console.log(`Schema generated at ${versionedOutputPath}`);
};

generateSchema().catch(console.error);

/**
 * AI-Powered Fix Generation Module
 *
 * Exports:
 * - FixGenerator: Generate code fixes using AI
 * - FixApplier: Safely apply fixes to files with backups and rollback
 *
 * @module ai-fixers
 */

const FixGenerator = require('./fix-generator');
const FixApplier = require('./fix-applier');

module.exports = {
  FixGenerator,
  FixApplier
};

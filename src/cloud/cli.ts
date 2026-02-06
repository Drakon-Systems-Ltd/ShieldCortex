import { getCloudConfig, setCloudConfig } from './config.js';

export function handleCloudConfig(args: string[]): void {
  if (args.includes('--cloud-status')) {
    const config = getCloudConfig();
    console.log('\nShieldCortex Cloud Configuration:');
    console.log(`  Enabled:  ${config.cloudEnabled ? 'Yes' : 'No'}`);
    console.log(`  API Key:  ${config.cloudApiKey ? config.cloudApiKey.substring(0, 12) + '...' : 'Not set'}`);
    console.log(`  Base URL: ${config.cloudBaseUrl}`);
    console.log('');
    return;
  }

  let changed = false;

  const keyIdx = args.indexOf('--cloud-api-key');
  if (keyIdx !== -1 && args[keyIdx + 1]) {
    setCloudConfig({ cloudApiKey: args[keyIdx + 1] });
    console.log('Cloud API key set.');
    changed = true;
  }

  const urlIdx = args.indexOf('--cloud-url');
  if (urlIdx !== -1 && args[urlIdx + 1]) {
    setCloudConfig({ cloudBaseUrl: args[urlIdx + 1] });
    console.log(`Cloud base URL set to: ${args[urlIdx + 1]}`);
    changed = true;
  }

  if (args.includes('--cloud-enable')) {
    setCloudConfig({ cloudEnabled: true });
    console.log('Cloud sync enabled.');
    changed = true;
  }

  if (args.includes('--cloud-disable')) {
    setCloudConfig({ cloudEnabled: false });
    console.log('Cloud sync disabled.');
    changed = true;
  }

  if (!changed) {
    console.log('Usage: npx shieldcortex config [options]');
    console.log('');
    console.log('Options:');
    console.log('  --cloud-api-key <key>  Set cloud API key');
    console.log('  --cloud-url <url>      Set cloud base URL');
    console.log('  --cloud-enable         Enable cloud sync');
    console.log('  --cloud-disable        Disable cloud sync');
    console.log('  --cloud-status         Show current configuration');
  }
}

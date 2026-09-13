'use client';

/**
 * Version Panel Component
 *
 * Displays current version, checks for updates, and allows
 * updating and restarting the server.
 */

import { useState } from 'react';
import {
  useVersion,
  useForceCheckForUpdates,
  usePerformUpdate,
  useRestartServer,
  VersionInfo,
} from '@/hooks/useMemories';
import { Button } from '@/components/ui/button';

type UpdateState = 'idle' | 'checking' | 'updating' | 'restarting' | 'success' | 'error';

export function VersionPanel() {
  const [updateState, setUpdateState] = useState<UpdateState>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showRestartPrompt, setShowRestartPrompt] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<VersionInfo | null>(null);

  const { data: versionData, isLoading: versionLoading } = useVersion();
  const checkMutation = useForceCheckForUpdates();
  const updateMutation = usePerformUpdate();
  const restartMutation = useRestartServer();

  const handleCheckUpdates = async () => {
    setUpdateState('checking');
    setErrorMessage(null);
    try {
      const result = await checkMutation.mutateAsync();
      setUpdateInfo(result);
      setUpdateState('idle');
    } catch {
      setErrorMessage('Failed to check for updates');
      setUpdateState('error');
    }
  };

  const handleUpdate = async () => {
    setUpdateState('updating');
    setErrorMessage(null);
    try {
      const result = await updateMutation.mutateAsync();
      if (result.success) {
        setUpdateState('success');
        if (result.requiresRestart) {
          setShowRestartPrompt(true);
        }
        // Clear update info since we just updated
        setUpdateInfo(null);
      } else {
        setErrorMessage(result.error || 'Update failed');
        setUpdateState('error');
      }
    } catch (err) {
      setErrorMessage('Update failed: ' + (err as Error).message);
      setUpdateState('error');
    }
  };

  const handleRestart = async () => {
    if (
      !confirm(
        'This will restart the server. The page will need to be refreshed after restart. Continue?'
      )
    ) {
      return;
    }

    setUpdateState('restarting');
    try {
      await restartMutation.mutateAsync();
      // Show message to refresh page - server will disconnect
      setErrorMessage(null);
    } catch {
      setErrorMessage('Failed to restart server');
      setUpdateState('error');
    }
  };

  if (versionLoading) {
    return (
      <div className="p-3 rounded-lg bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] animate-pulse">
        <div className="h-4 bg-[var(--sc-bg-elevated)] rounded w-24"></div>
      </div>
    );
  }

  const hasUpdate = updateInfo?.updateAvailable;
  const currentVersion = versionData?.version || 'unknown';
  const runningVersion = versionData?.runningVersion;
  const isStale = versionData?.stale === true;
  const latestVersion = updateInfo?.latestVersion;

  return (
    <div className="p-3 rounded-lg bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)]">
      {/* Version Display */}
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-[var(--sc-text-secondary)]">Version</span>
        <div className="flex items-center gap-2">
          <span className="text-sm font-mono text-[var(--sc-text-primary)]">v{currentVersion}</span>
          {hasUpdate && (
            <span className="px-1.5 py-0.5 text-xs rounded bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] border border-[var(--sc-cyan)]/30">
              Update available
            </span>
          )}
        </div>
      </div>

      {/* Stale Version Warning */}
      {isStale && (
        <div className="px-2 py-1.5 mb-3 rounded text-xs bg-[var(--sc-amber)]/20 border border-[var(--sc-amber)]/30 text-[var(--sc-amber)]">
          <div className="font-medium mb-0.5">Restart required</div>
          <div className="text-[var(--sc-amber)]/80">
            Running v{runningVersion} but v{currentVersion} is installed. Restart to load the new version.
          </div>
        </div>
      )}

      {/* Update Info */}
      {updateInfo && latestVersion && currentVersion !== latestVersion && (
        <div className="text-xs text-[var(--sc-text-muted)] mb-3">
          Latest: v{latestVersion}
          {updateInfo.cacheHit && <span className="text-[var(--sc-text-muted)]"> (cached)</span>}
        </div>
      )}

      {/* Error Message */}
      {errorMessage && (
        <div className="px-2 py-1.5 mb-3 rounded text-xs bg-[var(--sc-coral)]/20 border border-[var(--sc-coral)]/30 text-[var(--sc-coral)]">
          {errorMessage}
        </div>
      )}

      {/* Success Message with Restart Prompt */}
      {updateState === 'success' && showRestartPrompt && (
        <div className="px-2 py-1.5 mb-3 rounded text-xs bg-[var(--sc-cyan)]/20 border border-[var(--sc-cyan)]/30 text-[var(--sc-cyan)]">
          Update complete! Restart the server to apply changes.
        </div>
      )}

      {/* Restarting Message */}
      {updateState === 'restarting' && (
        <div className="px-2 py-1.5 mb-3 rounded text-xs bg-[var(--sc-coral)]/20 border border-[var(--sc-coral)]/30 text-[var(--sc-coral)]">
          Restarting server... Refresh the page in a few seconds.
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={handleCheckUpdates}
          disabled={checkMutation.isPending || updateState === 'updating'}
          className="flex-1 border-[var(--sc-border)] text-[var(--sc-text-primary)] hover:bg-[var(--sc-bg-elevated)]/20"
          title="Check npm for newer versions"
        >
          {checkMutation.isPending || updateState === 'checking' ? '...' : 'Check Updates'}
        </Button>

        {hasUpdate && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleUpdate}
            disabled={updateState === 'updating' || updateState === 'restarting'}
            className="flex-1 border-[var(--sc-cyan)] text-[var(--sc-cyan)] hover:bg-[var(--sc-cyan)]/20 hover:text-[var(--sc-cyan)]"
            title="Update to latest version via npm"
          >
            {updateState === 'updating' ? '...' : 'Update'}
          </Button>
        )}

        {(showRestartPrompt || isStale) && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleRestart}
            disabled={updateState === 'restarting'}
            className="flex-1 border-[var(--sc-coral)] text-[var(--sc-coral)] hover:bg-[var(--sc-coral)]/20 hover:text-[var(--sc-coral)]"
            title="Restart the server to apply updates"
          >
            {updateState === 'restarting' ? '...' : 'Restart'}
          </Button>
        )}
      </div>
    </div>
  );
}

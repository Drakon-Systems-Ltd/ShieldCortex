#!/bin/bash
# Uninstall claude-compact memory server
# Run this script to completely remove the memory server from Claude Code

set -e

echo "============================================"
echo "  Claude Memory Server Uninstaller"
echo "============================================"
echo ""

# Restore original settings
if [ -f ~/.claude/settings.json.backup-pre-memory ]; then
    cp ~/.claude/settings.json.backup-pre-memory ~/.claude/settings.json
    echo "[OK] Restored original settings.json"
else
    echo "[WARN] No backup found at ~/.claude/settings.json.backup-pre-memory"
    echo "       You may need to manually remove mcpServers.memory from settings.json"
fi

# Ask about database deletion
echo ""
read -p "Delete memory database (~/.claude-memory/)? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -d ~/.claude-memory ]; then
        rm -rf ~/.claude-memory
        echo "[OK] Deleted memory database"
    else
        echo "[INFO] No database found at ~/.claude-memory/"
    fi
else
    echo "[OK] Kept memory database (can be reused later)"
fi

# Clean up backup file
echo ""
read -p "Delete settings backup file? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f ~/.claude/settings.json.backup-pre-memory ]; then
        rm ~/.claude/settings.json.backup-pre-memory
        echo "[OK] Deleted backup file"
    fi
else
    echo "[OK] Kept backup file"
fi

echo ""
echo "============================================"
echo "  Uninstall complete!"
echo "============================================"
echo ""
echo "Restart Claude Code to apply changes."
echo ""
echo "If you want to reinstall later, run:"
echo "  cd /Users/michael/Development/claude-compact"
echo "  node dist/index.js --help"
echo ""

package permissions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch observes the permissions file with fsnotify and reloads it on change.
// It runs until the context is cancelled. After each successful reload the
// optional onChange callback is invoked (e.g. to re-sync grants into DuckDB).
//
// The watch is placed on the configured file path itself. This correctly
// handles both regular filesystem edits and Kubernetes ConfigMap/Secret
// volumes, where kubelet updates a file by swapping the symlink target behind
// the user-visible path. In the Kubernetes case the old inode is removed,
// producing a Remove/Rename event, so the watch is re-established on the new
// target before reloading. A short debounce coalesces bursts of events.
func (m *Manager) Watch(ctx context.Context, logger *slog.Logger, onChange func()) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}
	defer watcher.Close()

	addWatch := func() error {
		if err := watcher.Add(m.configPath); err != nil {
			return fmt.Errorf("failed to watch permissions file %q: %w", m.configPath, err)
		}
		return nil
	}

	if err := addWatch(); err != nil {
		return err
	}

	logger.Info("Watching permissions file for changes", "path", m.configPath)

	const debounce = 100 * time.Millisecond
	reloadTimer := time.NewTimer(0)
	<-reloadTimer.C
	defer reloadTimer.Stop()

	resetReloadTimer := func() {
		if !reloadTimer.Stop() {
			select {
			case <-reloadTimer.C:
			default:
			}
		}
		reloadTimer.Reset(debounce)
	}

	reload := func() {
		if err := m.Load(); err != nil {
			logger.Error("Failed to reload permissions", "error", err)
			return
		}
		logger.Info("Permissions reloaded", "path", m.configPath)
		if onChange != nil {
			onChange()
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return errors.New("permissions watcher event channel closed")
			}
			// Kubernetes ConfigMap/Secret volumes update a file by replacing
			// the real file behind a symlink, which surfaces as a Remove (or
			// Rename) event on the watched path. The inotify watch is tied to
			// the old inode, so it must be re-established on the new file
			// before we can keep watching.
			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				_ = watcher.Remove(m.configPath)
				if err := addWatch(); err != nil {
					logger.Error("Failed to re-establish permissions watch", "error", err)
					continue
				}
				resetReloadTimer()
				continue
			}
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) && !event.Has(fsnotify.Chmod) {
				continue
			}
			resetReloadTimer()
		case err, ok := <-watcher.Errors:
			if !ok {
				return errors.New("permissions watcher error channel closed")
			}
			logger.Error("Permissions watcher error", "error", err)
		case <-reloadTimer.C:
			reload()
		}
	}
}

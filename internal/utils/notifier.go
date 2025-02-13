/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package utils

import (
	"fmt"
	"log"

	"github.com/fsnotify/fsnotify"
)

// FileWatcher represents a file watcher that tracks changes to files.
// It is used to determine when the number of monitored files has changed.
type FileWatcher struct {
	watcher   *fsnotify.Watcher
	files     []string
	count     int
	lastCount int
}

// NewFileWatcher returns a new *FileWatcher that watches for changes on the given paths.
//
// The returned FileWatcher will run callbackFunc when any of its watched paths change.
func NewFileWatcher(paths ...string) *FileWatcher {
	fw := &FileWatcher{
		files: paths,
		count: 0,
	}
	go func() {
		_ = fw.watch()
	}()
	return fw
}

// WasTriggered returns whether the file watcher has detected changes.
//
// It checks if the current count of files differs from the last known count.
// If it does, the function refreshes the watch and returns true to indicate that new
// files have been added or changed. Otherwise, it returns false.
func (fw *FileWatcher) WasTriggered() bool {
	if fw.lastCount != fw.count {
		fw.lastCount = fw.count
		// kubernetes removes and creates a file when a mounted secret or configmap is changed
		// refresh will re-add the newly created files after they have been changed
		_ = fw.Refresh()
		return true
	}
	return false
}

// Refresh re-adds all watched files to the fsnotify Watcher.
//
// This is necessary after a restart or when new files are added to be watched,
// as the watcher forgets its previous watches. It will automatically remove any
// previously removed files that no longer exist on the filesystem.
func (fw *FileWatcher) Refresh() (err error) {
	// Notes from fsnotify.Watcher.Add():
	// - A path can only be watched once; watching it more than once is a no-op and will not return an error.
	// - Paths that do not yet exist on the filesystem cannot be watched.
	// - A watch will be automatically removed if the watched path is deleted or renamed. T
	for _, p := range fw.files {
		err = fw.watcher.Add(p)
		if err != nil {
			return fmt.Errorf("%q: %w", p, err)
		}
	}
	return nil
}

// Watch starts the file watcher. This method should be called when an instance
// of FileWatcher is initialized.
func (fw *FileWatcher) watch() (err error) {
	fw.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("issue %w while creating a watcher for these files: %v", err, fw.files)
	}
	defer fw.watcher.Close()

	go fw.watchLoop()
	if err = fw.Refresh(); err != nil {
		return err
	}

	<-make(chan struct{}) // Block forever
	return nil
}

// watchLoop is the inner loop function of FileWatcher that continuously monitors
// events from the file system and calls the callback function when a change is detected.
func (fw *FileWatcher) watchLoop() {
	for {
		select {
		case err, ok := <-fw.watcher.Errors:
			if !ok { // Channel was closed (i.e. Watcher.Close() was called).
				return
			}
			log.Printf("ERROR: %s", err)
		case e, ok := <-fw.watcher.Events:
			if !ok { // Channel was closed (i.e. Watcher.Close() was called).
				return
			}

			// Just print the event nicely aligned, and keep track how many
			// events we've seen.
			fw.count++
			log.Printf("secret notification: %3d/%3d %s", fw.count, fw.lastCount, e)
		}
	}
}

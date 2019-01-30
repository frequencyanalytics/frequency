package main

import (
	"os"
	"strings"
	"time"
)

func fileman() {
	const maxStorage = 95

	if !deleteOldFiles && !compressOldFiles {
		return
	}

	for {
		time.Sleep(2 * time.Minute)

		for _, propertyID := range eventPropertyIDs() {
			// All event files before today.
			files := eventFiles(propertyID, 1, time.Now().AddDate(0, 0, -1).Unix())

			if len(files) == 0 {
				continue
			}

			//
			// Delete files to avoid filling up storage.
			//
			if deleteOldFiles {
				di, err := NewDiskInfo(datadir)
				if err == nil {
					if di.UsedPercent() >= maxStorage {
						oldest := files[0]
						logger.Infof("fileman: deleting oldest file %q because storage is >%d%% full (%.1f)", oldest, maxStorage, di.UsedPercent())
						if err := os.Remove(oldest); err != nil {
							logger.Error(err)
							continue
						}
						files = files[1:]
					}
				} else if err != nil {
					logger.Error(err)
				}
			}

			//
			// Compress a completed file
			//
			if compressOldFiles {
				for _, filename := range files {
					if strings.HasSuffix(filename, ".events.gz") {
						continue
					}
					logger.Infof("gzipping %q", filename)
					if err := gzipit(filename); err != nil {
						logger.Error(err)
						continue
					}
					break // One per run
				}
			}
		}
	}
}

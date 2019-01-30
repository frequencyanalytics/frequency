package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"
)

type DiskInfo struct {
	free int64
	used int64
}

func (d *DiskInfo) Total() int64   { return d.free + d.used }
func (d *DiskInfo) TotalMB() int64 { return d.Total() / 1024 / 1024 }
func (d *DiskInfo) TotalGB() int64 { return d.TotalMB() / 1024 }

func (d *DiskInfo) Free() int64   { return d.free }
func (d *DiskInfo) FreeMB() int64 { return d.free / 1024 / 1024 }
func (d *DiskInfo) FreeGB() int64 { return d.FreeMB() / 1024 }

func (d *DiskInfo) Used() int64   { return d.used }
func (d *DiskInfo) UsedMB() int64 { return d.used / 1024 / 1024 }
func (d *DiskInfo) UsedGB() int64 { return d.UsedMB() / 1024 }

func (d *DiskInfo) UsedPercent() float64 {
	return (float64(d.used) / float64(d.Total())) * 100
}

func NewDiskInfo(path string) (*DiskInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, fmt.Errorf("diskinfo failed: %s", err)
	}
	free := stat.Bavail * uint64(stat.Bsize)
	used := (stat.Blocks * uint64(stat.Bsize)) - free
	return &DiskInfo{int64(free), int64(used)}, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(b)[:n]
}

func overwrite(filename string, data []byte, perm os.FileMode) error {
	f, err := ioutil.TempFile(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), perm); err != nil {
		return err
	}
	return os.Rename(f.Name(), filename)
}

func gzipit(filename string) error {
	if strings.HasSuffix(filename, ".gz") {
		return fmt.Errorf("file %s is already gzipped", filename)
	}

	tmp, err := ioutil.TempFile(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	src, err := os.Open(filename)
	if err != nil {
		return err
	}

	gz, _ := gzip.NewWriterLevel(tmp, gzip.BestSpeed)
	if _, err := io.Copy(gz, src); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filename+".gz"); err != nil {
		return err
	}
	return os.Remove(filename)
}

func bash(tmpl string, params interface{}) (string, error) {
	preamble := `
set -o nounset
set -o errexit
set -o pipefail
set -o xtrace
`
	t, err := template.New("template").Parse(preamble + tmpl)
	if err != nil {
		return "", err
	}
	var script bytes.Buffer
	err = t.Execute(&script, params)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	output, err := exec.CommandContext(ctx, "/bin/bash", "-c", string(script.Bytes())).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command failed: %s\n%s", err, string(output))
	}
	return string(output), nil
}

func normalizeBrowserName(name, os string) string {
	os = strings.Replace(os, "x86_64", "", -1)
	os = strings.Replace(os, "i686", "", -1)
	if strings.Contains(os, "CrOS") {
		os = "Chrome OS"
	}
	if strings.Contains(os, "Android") {
		os = "Android"
	}
	if strings.Contains(os, "iPad") {
		os = "iPad"
	}
	if strings.Contains(os, "iPhone") {
		os = "iPhone"
	}
	if strings.Contains(os, "Mac OS X") {
		os = "Mac OS X"
	}
	if strings.Contains(os, "Ubuntu") {
		os = "Linux"
	}
	if strings.Contains(os, "Windows") {
		os = "Windows"
	}
	//return fmt.Sprintf("%s - %s", os, name)
	return os
}

func botcheck(ua string) bool {
	return strings.Contains(ua, "http")
}

func lines(filename string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	count := 0
	separator := []byte{'\n'}
	for {
		c, err := f.Read(buf)
		count += bytes.Count(buf[:c], separator)
		if err == io.EOF {
			return count, nil
		} else if err != nil {
			return count, err
		}
	}

}

func du(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !fi.IsDir() {
			size += fi.Size()
		}
		return nil
	})
	return size, err
}

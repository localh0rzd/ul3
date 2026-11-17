//go:build linux || darwin || freebsd

package main

import "syscall"

// diskFree returns the bytes available to unprivileged users on dir's filesystem.
func diskFree(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

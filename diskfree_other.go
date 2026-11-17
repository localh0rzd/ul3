//go:build !(linux || darwin || freebsd)

package main

import "errors"

// diskFree is not implemented here; the low-disk guard is skipped.
func diskFree(string) (int64, error) { return 0, errors.ErrUnsupported }

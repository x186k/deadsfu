//go:build !race
// +build !race

package disrupt

import "unsafe"

const RaceEnabled = false

func RaceDisable() {}

func RaceEnable() {}

func RaceAcquire(p unsafe.Pointer) {}

func RaceReleaseMerge(p unsafe.Pointer) {}

func RaceRelease(p unsafe.Pointer) {}

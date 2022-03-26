//go:build race
// +build race

package disrupt

import "unsafe"

const RaceEnabled = true

//go:linkname RaceDisable runtime.RaceDisable
func RaceDisable()

//go:linkname RaceEnable runtime.RaceEnable
func RaceEnable()

//go:linkname RaceAcquire runtime.RaceAcquire
func RaceAcquire(p unsafe.Pointer)

//go:linkname RaceReleaseMerge runtime.RaceReleaseMerge
func RaceReleaseMerge(p unsafe.Pointer)

//go:linkname RaceRelease runtime.RaceRelease
func RaceRelease(p unsafe.Pointer)

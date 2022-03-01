package deadsfu

import "embed"

//go:embed html
var HtmlContent embed.FS

//go:embed deadsfu-binaries/idle-clip.zip
var IdleClipZipBytes []byte

//go:embed deadsfu-binaries/favicon_io/favicon.ico
var Favicon_ico []byte

//go:embed deadsfu-binaries/deadsfu-camera-not-available.mp4
var DeadsfuCameraNotAvailableMp4 []byte
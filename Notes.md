


# Design Notes

## minimalist logging philiosophy

- just three debug levels conceptually: debug, info, error
- try not to use fmt.Print*
- debug goes to stdout: log.Print*
- info goes to stderr info.Println("ingest webrtc up...")
- error goes to stderr elog.Println("janus timeout...")
- fatal goes to stderr: panic, etc. (println, etc)


Good article:
https://dave.cheney.net/2015/11/05/lets-talk-about-logging



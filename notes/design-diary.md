
# Design Diary

## 4/16/21  
- Working switching from 3 tracks to N (say, 100) tracks.
- Also considering the goroutine design.
- Ideally one goroutine per core or per subscriber for sending
- Per-subscriber state should only be touched by a single goroutine
- RX media is sent to N channels, where N is the number of goroutines, either num-cores or num-subs

Notes on gr-per-core:
- all media goes to all cores
- subs must be assigned to a single core
- no rx media filtering needed before send to chan
- may have advantages when moving to openssl/xdp
- the approach a salty C programmer would use
- subscriber state is independent of each other, so design is simple loop

Notes on gr-per-sub:
- dont necessarily want all media to all subs, pre-chan filtering might be optimal
- switching channels can be done with a message vs mutex/lock

What about gr-per-rx-track-per-core ?
- interesting
- open ssl loop
- then xdp it away

What about gr-per-rx-track ?
- NO
- basically what we have now
- the main issue, is that if we have one rx-track, all sending activity happens on a single GR, meaning you are not using your fancy 48 core CPU
- might mean multiple goroutines are contending for subscriber state, though :(, ie when switching channels

how does channel switch occur?
- happens on http handler goroutine




## 4/19/21 Notes on multi-core sending

- X tracks of inbound media (ie, 4 = 3 video, 1 audio)
- x is a particular track
- Y tracks of outbound media (ie, 10 sfus + 10 browsers = 40 + 20 = 60)
- workers waiting on Rx media and passing to Tx tracks seems right
- SFUs are simple as the rx->tx assignments are fixed for the life of the connection
- Browsers are not so simple to rx->tx assigments can change as the browser can change tracks
- inbound media must maintain ordering on the way to tx tracks (avoid races)
- would like to avoid mutexs that could contend, and in general. (can't avoid pion mutexes)
- switching between two rx tracks requires a mutex or a central goroutine. I choose central goroutine
- workers need to iterate sub's to send media OR contain/hide TX sub info. I choose contain.
- the main design issue/trickiness is that TX tracks can switch between different RX tracks, of which the timing of is conditioned on the incoming/pending RX track media packet being 'switchable'
- the conditioning is not the hard part
- the hard part is the migrating between tx-workers
- maybe its not so hard. we have a 'center' GR (goroutine)
- this is required in order to do switching without using a mux (mux or central is required due to ordered media requirement)
- the 'center' GR is controls switching
- when the Center determines and rtp.Packet is switchable+a track needs to be switched,
- it sends a 'stop-sending' sentinel to all workers and sends a 'start-sending' sentinal to the proper worker. thats all that is required if the workers don't need to touch mutex-shared-state related to the TX track!!!


Scenario 3rx chan, 10000tx chan all fed from rx#2
we would we not want all 10000tx chans to be fed on the same GR
SO, A SINGLE GR per RX does not work
must have multiple sendGR per RX

## 4/20/21 move WriteRTP off of OnIngress Goroutine, plus lift 3 RX track limit

- a single center gr would need to iterate the pending-change set in order

- there are two kinds of TX tracks: switchable and non-switchable

## 4/21/21





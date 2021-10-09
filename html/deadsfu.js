//@ts-check  
//The @ts-check statement above enables jsdoc typechecking
// https://stackoverflow.com/a/52076280/86375
// http://demo.unified-streaming.com/players/dash.js-2.4.1/build/jsdoc/jsdoc_cheat-sheet.pdf

let suburl = location.origin + '/sub'        // output from sfu
let puburl = location.origin + '/pub'          // input to sfu

// Wait for the page to load first
window.onload = function () {
    myOnload()
}

// 
var a = document.getElementById("gofullscreen")
a.onclick = function () {
    let video = document.getElementById("video1")
    if (video.requestFullscreen) {
        video.requestFullscreen()
    } else {
        // Toggle fullscreen in Safari for iPad
        // @ts-ignore
        if (video.webkitEnterFullScreen) {
            // @ts-ignore
            video.webkitEnterFullScreen()
        }
    }
    return false
}



async function myOnload() {
    const xstate = document.getElementById('xstate')
    const vidout = /** @type {HTMLVideoElement} */ (document.getElementById('video1'))
    const pc = await receive(xstate, vidout)
    document.title = "Receiving"
    while (true) {
        document.getElementById('rxtx').textContent = await getRxTxRate(pc)
        await new Promise(r => setTimeout(r, 3000))
    }
}









// prior to invoke transmit
// const gumopts = { video: { width: 1280, height: 720 }, audio: true }
// const stream = await navigator.mediaDevices.getUserMedia(gumopts)

// const xvid = /** @type {HTMLVideoElement} */ (document.getElementById('video1'))
// xvid.srcObject = stream
// let v=stream.getVideoTracks()[0]
// let a=stream.getAudioTracks()[0]
// let pc = transmit(v,a)
// const xstate = document.getElementById('xstate')
// pc.onconnectionstatechange = e => xstate.textContent = pc.connectionState
// while (true) {
//   document.getElementById('rxtx').textContent = await getRxTxRate(pc)
//   await new Promise(r => setTimeout(r, 3000))
//  }


/**
 * @param {MediaStreamTrack} video The video MST to send using WISH.
 * @param {MediaStreamTrack} audio The audio MST to send using WISH.
 * @returns {Promise<RTCPeerConnection>}
 */
async function transmit(video, audio) {
    console.debug("--transmit5")
    document.title = "Sending"


    try {

        //   var t0 = performance.now()
        //console.debug("delay of " + (performance.now() - t0) + "ms")
        let pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })
        pc.oniceconnectionstatechange = e => console.debug(pc.iceConnectionState)

        //pc.onicecandidate = event => { console.debug('ignore ice candidate') }

        pc.addTransceiver(video, { 'direction': 'sendonly' })
        pc.addTransceiver(audio, { 'direction': 'sendonly' })

        let desc = await pc.createOffer()
        await pc.setLocalDescription(desc)

        // XXXX consider wrapping with timeout promise
        const t0 = performance.now()
        await waitToCompleteIceGathering(pc,true)
        desc = pc.localDescription
        console.debug('ice gather blocked for N ms:', Math.ceil(performance.now() - t0))

        console.debug('sending N line offer:', desc.sdp.split(/\r\n|\r|\n/).length)
        let fetchopt =
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/sdp', },
            body: desc.sdp
        }
        let resp = await fetch(puburl, fetchopt)
        let resptext = await resp.text()
        if (resp.status != 202) {
            throw `SFU error: ${resptext} ${resp.status}`
            // pc.close()
            // return
        }
        console.debug('got N line answer:', resptext.split(/\r\n|\r|\n/).length)
        await pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: resptext }))

        return pc
    } catch (error) {
        console.error('Send Error:', error)
        //document.getElementById('errortext').textContent = error
        alert(error)
    }
}


/**
 * @param {RTCSessionDescription} desc The session description.
 * @returns {Promise<string>}
 */
async function sendSignalling(desc) {
    console.debug('sending N line offer:', desc.sdp.split(/\r\n|\r|\n/).length)
    let fetchopt =
    {
        method: 'POST',
        headers: { 'Content-Type': 'application/sdp', },
        body: desc.sdp
    }
    let resp = await fetch(suburl, fetchopt)
    let resptext = await resp.text()
    if (resp.status != 202) {
        throw `SFU error: ${resptext} ${resp.status}`
        // pc.close()
        // return
    }
    console.debug('got N line answer:', resptext.split(/\r\n|\r|\n/).length)
    return resptext
}


async function waitToCompleteIceGathering(pc, logPerformance) {
    const t0 = performance.now()

    let p = new Promise(resolve => {
        setTimeout(function () {
            resolve(pc.localDescription)
        }, 250)
        pc.addEventListener('icegatheringstatechange', e => (e.target.iceGatheringState === 'complete') && resolve(pc.localDescription));
    })

    if (logPerformance === true) {
        await p
        console.debug('ice gather blocked for N ms:', Math.ceil(performance.now() - t0))
    }
    return p
}






/**
 * @param {HTMLElement} status - The status element .innerText gets updatew.
 * @param {HTMLVideoElement} vidout - The video element for playback
 * @returns {Promise<RTCPeerConnection>}
 */
async function receive(status, vidout) {
    console.debug("--receive x3")



    try {
        const url = suburl

        let pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })
        pc.oniceconnectionstatechange = e => console.debug(pc.iceConnectionState)

        pc.onconnectionstatechange = e => {
            console.debug('>onconnectionstatechange', pc.connectionState)
            status.innerText = pc.connectionState
            if (pc.connectionState === "failed") {
                /* possibly reconfigure the connection in some way here */
                /* then request ICE restart */
                console.debug('restarting ice')
                pc.restartIce()
            }
        }


        let ntry = 0
        pc.onnegotiationneeded = async () => {
            console.debug('onnegotiationneeded')
            await pc.setLocalDescription(await pc.createOffer())
            await waitToCompleteIceGathering(pc,true)
            let ans = ''
            while (ans === '') {
                try {
                    ans = await sendSignalling(pc.localDescription)
                } catch (err) {
                    console.log(err)

                    status.innerText = ('retrying #' + ntry++)

                    await (new Promise(r => setTimeout(r, 2000)))
                }
            }

            await pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: ans }))
        }

        //must have addtransceiver to get m=video in sdp
        //addTransceiver() must be called before createOffer()
        pc.addTransceiver('video', { 'direction': 'recvonly' })
        pc.addTransceiver('audio', { 'direction': 'recvonly' })

        pc.ontrack = function (event) {
            let z = event.streams[0]
            console.debug('on track fired naudio', z.getAudioTracks().length)
            console.debug('on track fired nvideo', z.getVideoTracks().length)

            vidout.srcObject = event.streams[0]
            vidout.autoplay = true
            vidout.controls = true
            return false
        }
        // Go!
        pc.restartIce()

        console.debug('n senders in getsenders()', pc.getSenders())

        return pc
    } catch (error) {
        console.error('Receive Error:', error)
        //document.getElementById('errortext').textContent = error
        alert(error)
    }
}

var ratemap = new Map()

async function getRxTxRate(pc) {
    let rxrate = 0
    let txrate = 0
    try {
        if (typeof ratemap === 'undefined') {
            ratemap = new Map()
        }

        const results = await pc.getStats(null)
        results.forEach(report => {
            const now = report.timestamp


            let xtraDebug = true
            if (xtraDebug) {
                if (report.type === 'inbound-rtp' && report.kind === 'video') {
                    console.debug('frames: Nrx', report.framesReceived, 'Ndecode', report.framesDecoded, 'Nrx-Ndecode', report.framesReceived - report.framesDecoded)
                }
            }


            //debugging notes
            // if (typeof report.bytesReceived !== 'undefined') {
            //     console.debug(report.type, report.mediaType, report.bytesReceived)
            // }
            // if (typeof report.bytesTransmitted !== 'undefined') {
            //     console.debug(report.type, report.mediaType, report.bytesTransmitted)
            // }

            // NO!: if (report.type === 'outbound-rtp' && report.kind === 'video') {
            // we don't constrain rx/tx rate to just video, we include audio also
            if (report.type === 'outbound-rtp') {
                const bytes = report.bytesSent
                if (ratemap.has(report.ssrc)) { //report.id may also be a good key
                    const bytesPrev = ratemap.get(report.ssrc).bytesPrev
                    const timestampPrev = ratemap.get(report.ssrc).timestampPrev
                    const bitrate = 8 * (bytes - bytesPrev) / (now - timestampPrev);
                    txrate += bitrate
                    //console.debug('tx speed', report.ssrc, report.type, report.mediaType, bitrate)
                }
                ratemap.set(report.ssrc, { bytesPrev: bytes, timestampPrev: now })
            }
            if (report.type === 'inbound-rtp') {
                const bytes = report.bytesReceived
                if (ratemap.has(report.ssrc)) { //report.id may also be a good key
                    const bytesPrev = ratemap.get(report.ssrc).bytesPrev
                    const timestampPrev = ratemap.get(report.ssrc).timestampPrev
                    const bitrate = 8 * (bytes - bytesPrev) / (now - timestampPrev);
                    rxrate += bitrate
                    //console.debug('rx speed',report.ssrc, report.type, report.mediaType, bitrate)
                }
                ratemap.set(report.ssrc, { bytesPrev: bytes, timestampPrev: now })
            }
        })

    } catch (err) {
        console.error(err);
    }
    // we have kbps
    rxrate = Math.floor(rxrate)
    txrate = Math.floor(txrate)

    return `${rxrate}/${txrate} rx/tx kbps`
}


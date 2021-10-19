//@ts-check  
//The @ts-check statement above enables jsdoc typechecking
// https://stackoverflow.com/a/52076280/86375
// http://demo.unified-streaming.com/players/dash.js-2.4.1/build/jsdoc/jsdoc_cheat-sheet.pdf


/**
 * JSDoc type for a callback.
 *
 * @callback displayConnectionState
 * @param {string} message - The message to show to user.
 */



// Onload, launch send or receive WebRTC session, '?send' will
// trigger sending
window.onload = async function () {
    const suburl = location.origin + '/sub'        // output from sfu
    const puburl = location.origin + '/pub'          // input to sfu

    const vidElement = /** @type {HTMLVideoElement} */ (document.getElementById('video1'))
    const updatePageCallback = (/** @type {string} */ msg) => document.getElementById('xstate').innerText = msg
    const searchParams = new URLSearchParams(window.location.search)


    const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })
    pc.oniceconnectionstatechange = ev => console.debug(pc.iceConnectionState)
    pc.onconnectionstatechange = ev => onconnectionstatechange(ev, updatePageCallback)


    if (searchParams.has('send')) {

        pc.onnegotiationneeded = ev => onnegotiationneeded(ev, '/pub', updatePageCallback)

        /** @type {MediaStream} */
        var cameraStream
        try {
            cameraStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true })
        } catch (error) {
            alert('No camera found, please attach & reload page')
            return
        }

        vidElement.srcObject = cameraStream
        vidElement.play()

        const vidTrack = cameraStream.getVideoTracks()[0]
        const audTrack = cameraStream.getAudioTracks()[0]

        pc.addTransceiver(vidTrack, { 'direction': 'sendonly' })
        pc.addTransceiver(audTrack, { 'direction': 'sendonly' })

        document.title = "Sending"

    } else {
        pc.onnegotiationneeded = ev => onnegotiationneeded(ev, '/sub', updatePageCallback)

        pc.addTransceiver('video', { 'direction': 'recvonly' }) // build sdp
        pc.addTransceiver('audio', { 'direction': 'recvonly' }) // build sdp
        pc.ontrack = ev => vidElement.srcObject = ev.streams[0]

        document.title = "Receiving"

    }

    pc.restartIce()  // Start connecting!



    // @ts-ignore
    if (startGetStatsShipping) {
        // @ts-ignore
        startGetStatsShipping(pc)
    } else {
        console.debug('startGetStatsShipping() not invoked')
    }


    // declare func
    async function myCallback(id) {
        id.textContent = await getRxTxRate(pc)
        setTimeout(myCallback, 3000, id)        // milliseconds
    }

    // initiate timeout update loop
    myCallback(document.getElementById('rxtx'))


    // enable full screen nav-bar button
    document.getElementById("gofullscreen").onclick = fullScreen
}


function fullScreen() {
    const video = document.getElementById("video1")
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



/**
 * 
 * @param {Event} ev 
 * @param {string} url
 * @param {displayConnectionState} callback - A callback to run.
 */
async function onnegotiationneeded(ev, url, callback) {
    let pc = /** @type {RTCPeerConnection} */ (ev.target)

    console.debug('>onnegotiationneeded')

    const offer = await pc.createOffer()
    // https://blog.mozilla.org/webrtc/perfect-negotiation-in-webrtc/
    if (pc.signalingState != 'stable')
        return
    await pc.setLocalDescription(offer)
    await waitToCompleteIceGathering(pc, true)


    // retry loop
    let ntry = 0
    let ans = '' //check for v=0??
    while (ans === '') {
        try {
            ans = await sendSignalling(url, pc.localDescription)
        } catch (err) {
            callback('retrying #' + ntry++)
            console.log(err)
            await (new Promise(r => setTimeout(r, 2000)))
        }
    }

    await pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: ans }))
}


/**
 * 
 * @param {Event} ev 
 * @param {displayConnectionState} callback - A callback to run.
 */
function onconnectionstatechange(ev, callback) {
    let pc = /** @type {RTCPeerConnection} */ (ev.target)

    console.debug('>onconnectionstatechange:', pc.connectionState)


    /// XXX risky ????? cam  "perfect negotiation examples only show using "failed"
    if (pc.connectionState === "disconnected") {
        /* possibly reconfigure the connection in some way here */
        /* then request ICE restart */
        console.debug('restarting ice')
        pc.restartIce()
    }

    if (pc.connectionState === "failed") {
        /* possibly reconfigure the connection in some way here */
        /* then request ICE restart */
        console.debug('restarting ice')
        pc.restartIce()
    }
}



/**
 * @param {RTCSessionDescription} desc The session description.
 * @param {string} url Where to do WHIP or WHAP
 * @returns {Promise<string>}
 */
async function sendSignalling(url, desc) {
    console.debug('sending N line offer:', desc.sdp.split(/\r\n|\r|\n/).length)
    let fetchopt =
    {
        method: 'POST',
        headers: { 'Content-Type': 'application/sdp', },
        body: desc.sdp
    }
    let resp = await fetch(url, fetchopt)
    let resptext = await resp.text()
    if (resp.status != 202) {
        throw `SFU error: ${resptext} ${resp.status}`
        // pc.close()
        // return
    }
    console.debug('got N line answer:', resptext.split(/\r\n|\r|\n/).length)
    return resptext
}


/**
 * @param {RTCPeerConnection} pc
 * @param {boolean} logPerformance
 */
async function waitToCompleteIceGathering(pc, logPerformance) {
    const t0 = performance.now()

    let p = new Promise(resolve => {
        setTimeout(function () {
            resolve(pc.localDescription)
        }, 250)
        pc.addEventListener('icegatheringstatechange', ev => pc.iceGatheringState === 'complete' && resolve(pc.localDescription))
    })

    if (logPerformance === true) {
        await p
        console.debug('ice gather blocked for N ms:', Math.ceil(performance.now() - t0))
    }
    return p
}












/**
 * @param {RTCPeerConnection} pc
 */
async function getRxTxRate(pc) {
    let rxrate = 0
    let txrate = 0
    try {

        //@ts-ignore
        let ratemap = pc.ratemap
        if (typeof ratemap === 'undefined') {
            ratemap = new Map()
        }
        //@ts-ignore
        pc.ratemap = ratemap


        const results = await pc.getStats(null)

        //console.log(JSON.stringify(Object.fromEntries(await pc.getStats(null))))

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
                    const bitrate = 8 * (bytes - bytesPrev) / (now - timestampPrev)
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
                    const bitrate = 8 * (bytes - bytesPrev) / (now - timestampPrev)
                    rxrate += bitrate
                    //console.debug('rx speed',report.ssrc, report.type, report.mediaType, bitrate)
                }
                ratemap.set(report.ssrc, { bytesPrev: bytes, timestampPrev: now })
            }
        })

    } catch (err) {
        console.error(err)
    }
    // we have kbps
    rxrate = Math.floor(rxrate)
    txrate = Math.floor(txrate)

    return `${rxrate}/${txrate} rx/tx kbps`
}


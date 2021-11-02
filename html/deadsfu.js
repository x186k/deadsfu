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


    const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })

    const xstate = document.getElementById('xstate')
    //@ts-ignore  
    pc.addEventListener('retry-counter', ev => xstate.innerText = 'retrying #' + ev.detail)
    //firefox does not fire 'onconnectionstatechange' right now, so use ice...
    pc.addEventListener('iceconnectionstatechange', ev => xstate.innerText = pc.iceConnectionState)
    pc.addEventListener('iceconnectionstatechange', restartIceIfNeeded)


    const vidElement = /** @type {HTMLVideoElement} */ (document.getElementById('video1'))
    const searchParams = new URLSearchParams(window.location.search)
    if (searchParams.has('send')) {

        pc.onnegotiationneeded = ev => negotiate(ev, '/pub')

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
        pc.onnegotiationneeded = ev => negotiate(ev, '/sub')

        pc.addTransceiver('video', { 'direction': 'recvonly' }) // build sdp
        pc.addTransceiver('audio', { 'direction': 'recvonly' }) // build sdp
        pc.ontrack = function (event) {
            vidElement.srcObject = event.streams[0]
            vidElement.autoplay = true
            vidElement.controls = true
            console.log('**ontrack')
            return false
        }


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
    async function rxtxTimeoutCallback(id) {
        let rates = await getRxTxRate(pc)
        id.textContent = `${rates.rxrate}/${rates.txrate} rx/tx kbps`
        setTimeout(rxtxTimeoutCallback, 3000, id)        // milliseconds
    }

    // initiate timeout update loop
    rxtxTimeoutCallback(document.getElementById('rxtx'))


    // enable full screen nav-bar button

    document.getElementById("gofullscreen").onclick = (ev) => fullScreen(vidElement)

}

/**
 * 
 * @param {HTMLVideoElement}  vidElement
 */
function fullScreen(vidElement) {

    if (vidElement.requestFullscreen) {
        vidElement.requestFullscreen()
    } else {
        // Toggle fullscreen in Safari for iPad
        // @ts-ignore
        if (vidElement.webkitEnterFullScreen) {
            // @ts-ignore
            vidElement.webkitEnterFullScreen()
        }
    }
    return false
}

/**
 * 
 * @param {Event} ev 
 * @param {string} url
 * 
 *     https://blog.mozilla.org/webrtc/perfect-negotiation-in-webrtc/
 */
async function negotiate(ev, url) {
    let pc = /** @type {RTCPeerConnection} */ (ev.target)

    console.debug('>onnegotiationneeded')

    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    let ofr = await waitToCompleteIceGathering(pc, true)

    let ntry = 0
    let ans = ''
    while (ans === '') {
        try {
            ans = await sendSignalling(url, ofr)
            await pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: ans }))
        } catch {
            ntry = ntry + 1
            const event = new CustomEvent('retry-counter', { detail: ntry })
            pc.dispatchEvent(event)
            await (new Promise(r => setTimeout(r, 2000)))
        }
    }
}




/**
 * @param {Event} event 
 */
function restartIceIfNeeded(event) {
    let pc = /** @type {RTCPeerConnection} */ (event.target)

    if (pc.iceConnectionState === "disconnected") {   //'failed' is also an option
        console.debug('*** restarting ice')
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
        pc.onicegatheringstatechange = ev => pc.iceGatheringState === 'complete' && resolve(pc.localDescription)
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

        //console.debug_(JSON.stringify(Object.fromEntries(await pc.getStats(null))))

        results.forEach(report => {
            const now = report.timestamp


            let xtraDebug = false
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

    return {
        rxrate,
        txrate
    }
}


//@ts-check  
//The @ts-check statement above enables jsdoc typechecking
// https://stackoverflow.com/a/52076280/86375
// http://demo.unified-streaming.com/players/dash.js-2.4.1/build/jsdoc/jsdoc_cheat-sheet.pdf




import * as whipwhap from "./whip-whap-js/whip-whap-js.js";




// Onload, launch send or receive WebRTC session, adding '?send' or '&send' to url will
// trigger sending
window.onload = async function () {


    const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })

    const xstate = document.getElementById('xstate')
    //@ts-ignore  
    pc.addEventListener('retry-counter', ev => xstate.innerText = 'retrying #' + ev.detail)
    //firefox does not fire 'onconnectionstatechange' right now, so use ice...
    pc.addEventListener('iceconnectionstatechange', ev => xstate.innerText = pc.iceConnectionState)
    pc.addEventListener('iceconnectionstatechange', whipwhap.restartIceIfNeeded)


    const vidElement = /** @type {HTMLVideoElement} */ (document.getElementById('video1'))
    const searchParams = new URLSearchParams(window.location.search)
    if (searchParams.has('send')) {

        pc.onnegotiationneeded = ev => whipwhap.negotiate(ev, '/pub')

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
        pc.onnegotiationneeded = ev => whipwhap.negotiate(ev, '/sub')

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


    const rxtxSpan = document.getElementById('rxtx')

    // declare func
    async function rxtxTimeoutCallback() {
        let rates = await whipwhap.getRxTxRate(pc)
        rxtxSpan.textContent = `${rates.rxrate}/${rates.txrate} rx/tx kbps`
        setTimeout(rxtxTimeoutCallback, 3000)        // milliseconds
    }

    // initiate timeout update loop
    rxtxTimeoutCallback()


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

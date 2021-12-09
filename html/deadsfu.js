//@ts-check  
//The @ts-check statement above enables jsdoc typechecking
// https://stackoverflow.com/a/52076280/86375
// http://demo.unified-streaming.com/players/dash.js-2.4.1/build/jsdoc/jsdoc_cheat-sheet.pdf


import * as whipwhap from "./whip-whap-js/whip-whap-js.js"


// Onload, launch send or receive WebRTC session, adding '?send' or '&send' to url will
// trigger sending
window.onload = async function () {


    let pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })

    const xstate = document.getElementById('xstate')

    pc.addEventListener('downtime-msg', function (ev) {
        //@ts-ignore  
        let nsec = ev.detail.numsec; let status = ev.detail.status
        let time = (new Date(nsec * 1000)).toISOString().substr(11, 8)
        xstate.innerText = `downtime: ${time} httpcode: ${status}`
    })
    //firefox does not fire 'onconnectionstatechange' right now, so use ice...
    pc.addEventListener('iceconnectionstatechange', ev => xstate.innerText = pc.iceConnectionState)
    pc.addEventListener('iceconnectionstatechange', whipwhap.handleIceStateChange)


    let video1 = /** @type {HTMLVideoElement} */ (document.getElementById('video1'))
    let searchParams = new URLSearchParams(window.location.search)
    let bearerToken = searchParams.get('access_token')
    //let roomname = window.location.pathname
    let roomname = searchParams.get('room')
    if (!roomname) {
        roomname = "mainroom"
    }

    if (searchParams.has('send')) {
        let whipUrl = '/whip?room=' + roomname

        pc.addEventListener('negotiationneeded', ev => whipwhap.handleNegotiationNeeded(ev, whipUrl, bearerToken))

        /** @type {MediaStream} */
        var gum
        try {
            gum = await navigator.mediaDevices.getUserMedia({ audio: true, video: true })
        } catch (error) {
            alert('No camera found, please attach & reload page')
            return
        }

        video1.srcObject = gum
        video1.play()

        pc.addTransceiver(gum.getVideoTracks()[0], { 'direction': 'sendonly' })
        pc.addTransceiver(gum.getAudioTracks()[0], { 'direction': 'sendonly' })

        document.title = "Sending"

    } else {
        let whapUrl = '/whap?room=' + roomname

        // console.debug(newurl.searchParams.get('room')) // we just pass along 'room'

        pc.addEventListener('negotiationneeded', ev => whipwhap.handleNegotiationNeeded(ev, whapUrl, bearerToken))

        pc.addTransceiver('video', { 'direction': 'recvonly' }) // build sdp
        pc.addTransceiver('audio', { 'direction': 'recvonly' }) // build sdp

        pc.ontrack = ev => {
            video1.srcObject = ev.streams[0]
            // want to remove these someday 11.7.21 cam
            // video1.autoplay = true
            // video1.controls = true
            // return false
        }




        document.title = "Receiving"

    }

    // not needed!
    //pc.restartIce()  // Start connecting!



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
        let rates = await whipwhap.helperGetRxTxRate(pc)
        rxtxSpan.textContent = `${rates.rxrate}/${rates.txrate} rx/tx kbps`
        setTimeout(rxtxTimeoutCallback, 3000)        // milliseconds
    }

    // initiate timeout update loop
    rxtxTimeoutCallback()


    // enable full screen nav-bar button

    document.getElementById("gofullscreen").onclick = (ev) => fullScreen(video1)

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

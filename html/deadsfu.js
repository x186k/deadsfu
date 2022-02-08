//@ts-check  
//The @ts-check statement above enables jsdoc typechecking
// https://stackoverflow.com/a/52076280/86375
// http://demo.unified-streaming.com/players/dash.js-2.4.1/build/jsdoc/jsdoc_cheat-sheet.pdf


import * as whipwhap from "./whip-whap-js/whip-whap-js.js"

function uuidv4() {
    //@ts-ignore
    return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
        (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    )
}


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
    let mp4 = searchParams.get('mp4')
    // no, DRY: the go code does this also
    // if (!roomname) {
    //     roomname = "mainroom"
    // }
    if (!roomname) {
        roomname = ""
    }
    //console.log(555, roomname)

    let headers = new Headers()
    if (typeof bearerToken === 'string') { // may be null or undefined
        headers.set('Authorization', `Bearer ${bearerToken}`)
    }


    if (location.pathname == '/send/' || location.pathname == '/send') {
        let whipUrl = '/whip?room=' + roomname

        pc.addEventListener('negotiationneeded', ev => whipwhap.handleNegotiationNeeded(ev, whipUrl, headers))

        /** @type {MediaStream} */
        var mediaStream

        //no camera available
        //camera available on localhost in some instances, so https check not reliable
        //if (location.protocol !== 'https:') {
        if (mp4) {
            video1.src = mp4
            video1.loop = true
            video1.crossOrigin = 'anonymous'
            await video1.play()
            //@ts-ignore
            mediaStream = video1.captureStream()
        } else if (!navigator.mediaDevices) {
            video1.src = '/no-camera.mp4'
            video1.loop = true
            video1.crossOrigin = 'anonymous'
            await video1.play()
            //@ts-ignore
            mediaStream = video1.captureStream()
        } else {
            try {
                mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true })
                video1.srcObject = mediaStream
                video1.play()
            } catch (error) {
                alert('Camera setup failed:' + error)
                return
            }

        }



        pc.addTransceiver(mediaStream.getVideoTracks()[0], { 'direction': 'sendonly' })
        pc.addTransceiver(mediaStream.getAudioTracks()[0], { 'direction': 'sendonly' })

        document.title = "Sending"

    } else {
        const uuidRE = /^([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[0-9a-d][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i
        let subuuid = searchParams.get('subuuid')

        if (!uuidRE.test(subuuid)) {
            subuuid = uuidv4()
        }
        window.location.hash = '?subuuid=' + subuuid
        startRoomListFetchLoop(headers, subuuid)

        let whapUrl = '/whap?room=' + roomname

        headers.set('X-deadsfu-subuuid', subuuid) //sfu also accepts param &subuuid=..., but this is more secure

        // console.debug(newurl.searchParams.get('room')) // we just pass along 'room'

        pc.addEventListener('negotiationneeded', ev => whipwhap.handleNegotiationNeeded(ev, whapUrl, headers))

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
        let qualityLim = ''
        if (rates.qualityLimitation == true) {
            qualityLim = 'QL'
        }
        rxtxSpan.textContent = `${rates.rxrate}/${rates.txrate} rx/tx kbps ${qualityLim}`

        if (pc.signalingState == 'closed') {
            //this two lines are a desparate way to handle the pixelbook
            //laptop lid close/reopen
            // after this happens, the pc will be closed,
            // and pc.restartIce() does nothing.
            // this leaves us two choices: 1. create a new PC, 2. reload the page.
            // we choose #2 at this time.
            location.hash = 'closereloadlaptoplid'
            location.reload()
            // pc.restartIce()  this doesnt work after pixelbook lid closed/opened
            // , maybe pc.restartIce() never works from a 'closed' PC
        }


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


/**
* @param {Headers} hdrs could contain 'Authorization'
 * @param {string} roomname
 * @param {string} subuuid
 */
function switchRoom(hdrs, roomname, subuuid) {
    console.debug('** switchroom')
    let opt = {
        method: 'GET',
        headers: hdrs,
        /** @type RequestCache */  cache: "no-store"
    }

    var url = new URL('/switchRoom', location.origin)
    url.searchParams.set('room', roomname)
    url.searchParams.set('subuuid', subuuid)

    //console.log(8888,url.href)
    fetch(url.href)
}
//@ts-ignore
window.switchRoom = switchRoom




/**
 * @param {Headers} hdrs could contain 'Authorization'
 * @param {string} subuuid
 */
async function startRoomListFetchLoop(hdrs, subuuid) {

    setTimeout(myCallback, 0, 'xx')  //no delay

    /**
     *  @param {string} serial this number is used to block by server
     */
    async function myCallback(serial) {
        let url = '/getRoomList?serial=' + serial

        let opt = {
            method: 'GET',
            headers: hdrs,
            /** @type RequestCache */  cache: "no-store"
        }


        let resp = { status: -1 }
        try { // without try/catch, a thrown except from fetch exits our 'thread'
            //console.log(888, url)
            resp = await fetch(url, opt)
        } catch (error) {
            ;  // not needed console.log(error)
        }
        //console.log(111, resp.status)
        if (resp.status == 200) {
            let json = await resp.text()
            let obj = JSON.parse(json)
            //console.debug('json', json)
            //console.debug('jsono', obj)
            updateSourcesNav(hdrs, obj.rooms, subuuid)
            setTimeout(myCallback, 0, obj.serial)
        } else {
            // failure
            setTimeout(myCallback, 2000) // wait two sec before try again
        }
    }
}

/**
 * @param {Headers} hdrs could contain 'Authorization'
 * @param {Array} roomnames
 * @param {string} subuuid
 */
function updateSourcesNav(hdrs, roomnames, subuuid) {

    let p = document.getElementById('sources-proto')
    let div = document.getElementById("sources-div")

    while (div.firstChild) {
        div.removeChild(div.firstChild);
    }

    roomnames.forEach(v => {
        //console.log(333, v)
        let b = /** @type HTMLElement */ (p.cloneNode(true))
        b.id = ''
        b.hidden = false
        let bb = /** @type HTMLAnchorElement */ (b.firstChild)

        bb.href = "javascript:void(0)"
        bb.onclick = function () { switchRoom(hdrs, v, subuuid) }
        bb.innerText = v

        //console.debug('**', b.outerHTML)
        //console.debug('**', bb.outerHTML)

        //bb.innerText = v
        //console.debug(99, bb.innerText)
        div.appendChild(b)

    });



}


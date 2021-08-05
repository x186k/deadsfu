# Brutal Cam Theme

I'm afraid is what happens when you let a back-end developer design a theme.

A brutalist, minimalist theme. (I think)

## Installation

You can fork or clone the repo.
If you do a github GUI fork, then clone your fork of the repo,
you can get updates (if any) to this theme by using the Github GUI.

Basic way to clone and view site:

git clone https://github.com/cameronelliott/brutal-cam

cd brutal-cam


Server for working with live-reload, open your browser to http://127.0.0.1:4000
```bash
docker run --rm -it -v $PWD:/srv/jekyll -p 4000:4000 -p 35729:35729 jekyll/builder:latest jekyll serve --livereload
```

Build to _site
```bash
docker run --rm -it -v $PWD:/srv/jekyll -p 127.0.0.1:4000:4000 jekyll/builder:latest jekyll build
```
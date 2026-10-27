package encryptor

import (
	"errors"
	"io"
)

// maxProbeBytes caps how much of a stream is held in memory while trying
// candidate keys against its header. Encryption headers (PGP key packets,
// the age header) are a few hundred bytes to a few KiB.
const maxProbeBytes = 1 << 20

var errProbeTooLarge = errors.New("encryptor: encryption header exceeds 1 MiB")

// replayReader records what is read from src while probing, so that several
// key candidates can each parse the header from the start. After commit it
// replays the recorded bytes once, then reads src directly.
type replayReader struct {
	src       io.Reader
	buf       []byte
	pos       int
	recording bool
}

func newReplayReader(src io.Reader) *replayReader {
	return &replayReader{src: src, recording: true}
}

func (r *replayReader) Read(p []byte) (int, error) {
	if r.pos < len(r.buf) {
		n := copy(p, r.buf[r.pos:])
		r.pos += n
		if !r.recording && r.pos == len(r.buf) {
			r.buf, r.pos = nil, 0
		}
		return n, nil
	}
	if !r.recording {
		return r.src.Read(p)
	}
	if room := maxProbeBytes - len(r.buf); room <= 0 {
		return 0, errProbeTooLarge
	} else if len(p) > room {
		p = p[:room]
	}
	n, err := r.src.Read(p)
	r.buf = append(r.buf, p[:n]...)
	r.pos = len(r.buf)
	return n, err
}

// rewind restarts reading from the first recorded byte.
func (r *replayReader) rewind() { r.pos = 0 }

// commit stops recording: the remaining recorded bytes are replayed, then src
// is read directly.
func (r *replayReader) commit() {
	r.recording = false
	if r.pos == len(r.buf) {
		r.buf, r.pos = nil, 0
	}
}

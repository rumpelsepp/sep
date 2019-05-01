package sep

import (
	"io"
	"sync"

	log "git.sr.ht/~rumpelsepp/logging"
)

// TODO: error
func BidirectCopy(left io.ReadWriteCloser, right io.ReadWriteCloser) (int, int, error, error) {
	var (
		n1   = 0
		n2   = 0
		err1 error
		err2 error
		wg   sync.WaitGroup
	)

	wg.Add(2)

	go func() {
		if n, err := io.Copy(right, left); err != nil {
			log.Debugln(err)
			err1 = err
		} else {
			n1 = int(n)
		}

		right.Close()
		wg.Done()
	}()

	go func() {
		if n, err := io.Copy(left, right); err != nil {
			log.Debugln(err)
			err2 = err
		} else {
			n2 = int(n)
		}

		left.Close()
		wg.Done()
	}()

	wg.Wait()

	return n1, n2, err1, err2
}

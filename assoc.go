package sep

import "io"

type Association interface {
	Serve() (int, int, error, error)
}

type BidirectAssociation struct {
	Left  io.ReadWriteCloser
	Right io.ReadWriteCloser
}

// TODO: Error Codes!!
func (a *BidirectAssociation) Serve() (int, int, error, error) {
	return BidirectCopy(a.Left, a.Right)
}

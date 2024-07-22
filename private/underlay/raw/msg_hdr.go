package raw

import (
	"golang.org/x/sys/unix"
)

func MakeReadMessages(n, oobn int) (sas, oobs [][]byte, iovs []unix.Iovec, hs []Mmsghdr) {
	hs = make([]Mmsghdr, 0, n)
	sas = make([][]byte, 0, n)
	iovs = make([]unix.Iovec, 0, n)
	oobs = make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		var oob []byte
		if oobn > 0 {
			oob = make([]byte, oobn)
		}

		var iov unix.Iovec
		iov.Base = &oob[0]
		iov.SetLen(oobn)

		sa := make([]byte, unix.SizeofSockaddrLinklayer)
		h := Mmsghdr{
			Hdr: unix.Msghdr{
				Name:    &sa[0],
				Namelen: uint32(len(sa)),
				Iov:     &iov,
				Iovlen:  1},
		}
		hs = append(hs, h)
		sas = append(sas, sa)
		iovs = append(iovs, iov)
		oobs = append(oobs, oob)
	}
	return sas, oobs, iovs, hs
}

func MakeSendMessages(batchSize int) ([]Mmsghdr, []unix.Iovec) {
	msgs := make([]Mmsghdr, batchSize)
	iovecs := make([]unix.Iovec, batchSize*2) // 1 iovec for the payload, 1 for the header

	for i := range msgs {
		msgs[i].Hdr.Iov = &iovecs[i*2]
		msgs[i].Hdr.SetIovlen(2)
		msgs[i].Hdr.Namelen = uint32(unix.SizeofSockaddrLinklayer)
	}
	return msgs, iovecs
}

type Mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

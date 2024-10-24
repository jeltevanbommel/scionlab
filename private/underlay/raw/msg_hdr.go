package raw

import (
	"golang.org/x/sys/unix"
)

func MakeReadMessages(batchSize, oobn int) (iovs []unix.Iovec, hs []Mmsghdr) {
	hs = make([]Mmsghdr, 0, batchSize)
	iovs = make([]unix.Iovec, 0, batchSize)
	for i := 0; i < batchSize; i++ {
		var oob []byte
		if oobn > 0 {
			oob = make([]byte, oobn)
		}
		var iov unix.Iovec
		//if len(pktBuffs[i]) > 0 {
		//	iov.Base = &pktBuffs[i][0]
		//	iov.SetLen(len(pktBuffs[i]))
		//}
		sa := make([]byte, unix.SizeofSockaddrLinklayer)
		h := Mmsghdr{
			Hdr: unix.Msghdr{
				Name:       &sa[0],
				Namelen:    uint32(len(sa)),
				Iov:        &iov,
				Iovlen:     1,
				Control:    &oob[0],
				Controllen: uint64(len(oob)),
			},
		}
		hs = append(hs, h)
		iovs = append(iovs, iov)
	}
	return iovs, hs
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

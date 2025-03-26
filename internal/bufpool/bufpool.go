package bufpool

import "sync"

type BufPool interface {
	Get() []byte
	Put([]byte)
}

type pool struct {
	pool *sync.Pool
}

func New(size int) BufPool {
	return &pool{
		&sync.Pool{
			New: func() any {
				return make([]byte, size)
			},
		},
	}
}

func (p *pool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *pool) Put(b []byte) {
	if cap(b) == 0 || len(b) != cap(b) {
		return
	}
	p.pool.Put(b)
}

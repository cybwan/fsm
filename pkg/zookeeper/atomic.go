package zookeeper

import "sync/atomic"

// nocmp is an uncomparable struct. Embed this inside another struct to make
// it uncomparable.
//
//	type Foo struct {
//	  nocmp
//	  // ...
//	}
//
// This DOES NOT:
//
//   - Disallow shallow copies of structs
//   - Disallow comparison of pointers to uncomparable structs
type nocmp [0]func()

// Int32 is an atomic wrapper around int32.
type Int32 struct {
	_ nocmp // disallow non-atomic comparison

	v int32
}

// NewInt32 creates a new Int32.
func NewInt32(val int32) *Int32 {
	return &Int32{v: val}
}

// Load atomically loads the wrapped value.
func (i *Int32) Load() int32 {
	return atomic.LoadInt32(&i.v)
}

// Add atomically adds to the wrapped int32 and returns the new value.
func (i *Int32) Add(delta int32) int32 {
	return atomic.AddInt32(&i.v, delta)
}

// Sub atomically subtracts from the wrapped int32 and returns the new value.
func (i *Int32) Sub(delta int32) int32 {
	return atomic.AddInt32(&i.v, -delta)
}

// Inc atomically increments the wrapped int32 and returns the new value.
func (i *Int32) Inc() int32 {
	return i.Add(1)
}

// Dec atomically decrements the wrapped int32 and returns the new value.
func (i *Int32) Dec() int32 {
	return i.Sub(1)
}

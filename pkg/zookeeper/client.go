package zookeeper

import (
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dubbogo/go-zookeeper/zk"
	"github.com/pkg/errors"
)

var (
	zkClientPool   clientPool
	clientPoolOnce sync.Once

	// ErrNilZkClientConn no conn error
	ErrNilZkClientConn = errors.New("Zookeeper Client{conn} is nil")
	ErrStatIsNil       = errors.New("Stat of the node is nil")
)

// Client represents zookeeper Client Configuration
type Client struct {
	name              string
	ZkAddrs           []string
	sync.RWMutex      // for conn
	Conn              *zk.Conn
	activeNumber      uint32
	Timeout           time.Duration
	Wait              sync.WaitGroup
	valid             uint32
	share             bool
	initialized       uint32
	reconnectCh       chan struct{}
	eventRegistry     map[string][]chan zk.Event
	eventRegistryLock sync.RWMutex
	zkEventHandler    EventHandler
	Session           <-chan zk.Event
}

type clientPool struct {
	sync.Mutex
	zkClient map[string]*Client
}

// EventHandler interface
type EventHandler interface {
	HandleEvent(z *Client)
}

// DefaultHandler is default handler for zk event
type DefaultHandler struct{}

// StateToString will transfer zk state to string
func StateToString(state zk.State) string {
	switch state {
	case zk.StateDisconnected:
		return "zookeeper disconnected"
	case zk.StateConnecting:
		return "zookeeper connecting"
	case zk.StateAuthFailed:
		return "zookeeper auth failed"
	case zk.StateConnectedReadOnly:
		return "zookeeper connect readonly"
	case zk.StateSaslAuthenticated:
		return "zookeeper sasl authenticated"
	case zk.StateExpired:
		return "zookeeper connection expired"
	case zk.StateConnected:
		return "zookeeper connected"
	case zk.StateHasSession:
		return "zookeeper has Session"
	case zk.StateUnknown:
		return "zookeeper unknown state"
	default:
		return state.String()
	}
}

func initClientPool() {
	zkClientPool.zkClient = make(map[string]*Client)
}

// NewClient will create a Client
func NewClient(name string, zkAddrs []string, share bool, opts ...zkClientOption) (*Client, error) {
	if !share {
		return newClient(name, zkAddrs, share, opts...)
	}
	clientPoolOnce.Do(initClientPool)
	zkClientPool.Lock()
	defer zkClientPool.Unlock()
	if zkClient, ok := zkClientPool.zkClient[name]; ok {
		zkClient.activeNumber++
		return zkClient, nil
	}
	newZkClient, err := newClient(name, zkAddrs, share, opts...)
	if err != nil {
		return nil, err
	}
	zkClientPool.zkClient[name] = newZkClient
	return newZkClient, nil
}

func newClient(name string, zkAddrs []string, share bool, opts ...zkClientOption) (*Client, error) {
	newZkClient := &Client{
		name:           name,
		ZkAddrs:        zkAddrs,
		activeNumber:   0,
		share:          share,
		reconnectCh:    make(chan struct{}),
		eventRegistry:  make(map[string][]chan zk.Event),
		Session:        make(<-chan zk.Event),
		zkEventHandler: &DefaultHandler{},
	}
	for _, opt := range opts {
		opt(newZkClient)
	}
	err := newZkClient.createConn()
	if err != nil {
		return nil, err
	}
	newZkClient.activeNumber++
	return newZkClient, nil
}

// nolint
func (z *Client) createConn() error {
	var err error

	// connect to zookeeper
	z.Conn, z.Session, err = zk.Connect(z.ZkAddrs, z.Timeout)
	if err != nil {
		return err
	}
	atomic.StoreUint32(&z.valid, 1)
	go z.zkEventHandler.HandleEvent(z)
	return nil
}

// HandleEvent handles zookeeper events
// nolint
func (d *DefaultHandler) HandleEvent(z *Client) {
	var (
		ok    bool
		state int
		event zk.Event
	)
	for {
		select {
		case event, ok = <-z.Session:
			if !ok {
				// channel already closed
				return
			}
			switch event.State {
			case zk.StateDisconnected:
				atomic.StoreUint32(&z.valid, 0)
			case zk.StateConnected:
				z.eventRegistryLock.RLock()
				for path, a := range z.eventRegistry {
					if strings.HasPrefix(event.Path, path) {
						for _, e := range a {
							e <- event
						}
					}
				}
				z.eventRegistryLock.RUnlock()
			case zk.StateConnecting, zk.StateHasSession:
				if state == (int)(zk.StateHasSession) {
					continue
				}
				if event.State == zk.StateHasSession {
					atomic.StoreUint32(&z.valid, 1)
					//if this is the first connection, don't trigger reconnect event
					if !atomic.CompareAndSwapUint32(&z.initialized, 0, 1) {
						close(z.reconnectCh)
						z.reconnectCh = make(chan struct{})
					}
				}
				z.eventRegistryLock.RLock()
				if a, ok := z.eventRegistry[event.Path]; ok && 0 < len(a) {
					for _, e := range a {
						e <- event
					}
				}
				z.eventRegistryLock.RUnlock()
			}
			state = (int)(event.State)
		}
	}
}

// RegisterEvent registers zookeeper events
func (z *Client) RegisterEvent(zkPath string, event chan zk.Event) {
	if zkPath == "" {
		return
	}

	z.eventRegistryLock.Lock()
	defer z.eventRegistryLock.Unlock()
	a := z.eventRegistry[zkPath]
	a = append(a, event)
	z.eventRegistry[zkPath] = a
}

// UnregisterEvent unregisters zookeeper events
func (z *Client) UnregisterEvent(zkPath string, event chan zk.Event) {
	if zkPath == "" {
		return
	}

	z.eventRegistryLock.Lock()
	defer z.eventRegistryLock.Unlock()
	infoList, ok := z.eventRegistry[zkPath]
	if !ok {
		return
	}
	for i, e := range infoList {
		if e == event {
			infoList = append(infoList[:i], infoList[i+1:]...)
		}
	}
	if len(infoList) == 0 {
		delete(z.eventRegistry, zkPath)
	} else {
		z.eventRegistry[zkPath] = infoList
	}
}

// ConnValid validates zookeeper connection
func (z *Client) ConnValid() bool {
	return atomic.LoadUint32(&z.valid) == 1
}

// Create will create the node recursively, which means that if the parent node is absent,
// it will create parent node first.
// And the value for the basePath is ""
func (z *Client) Create(basePath string) error {
	return z.CreateWithValue(basePath, []byte{})
}

// CreateWithValue will create the node recursively, which means that if the parent node is absent,
// it will create parent node first.
// basePath should start with "/"
func (z *Client) CreateWithValue(basePath string, value []byte) error {
	conn := z.getConn()
	if conn == nil {
		return ErrNilZkClientConn
	}

	if !strings.HasPrefix(basePath, string(os.PathSeparator)) {
		basePath = string(os.PathSeparator) + basePath
	}
	paths := strings.Split(basePath, string(os.PathSeparator))
	// Check the ancestor's path
	for idx := 2; idx < len(paths); idx++ {
		tmpPath := strings.Join(paths[:idx], string(os.PathSeparator))
		_, err := conn.Create(tmpPath, []byte{}, 0, zk.WorldACL(zk.PermAll))
		if err != nil && !errors.Is(err, zk.ErrNodeExists) {
			return errors.WithMessagef(err, "Error while invoking zk.Create(path:%s), the reason maybe is: ", tmpPath)
		}
	}

	_, err := conn.Create(basePath, value, 0, zk.WorldACL(zk.PermAll))
	if err != nil {
		return err
	}
	return nil
}

// CreateTempWithValue will create the node recursively, which means that if the parent node is absent,
// it will create parent node first，and set value in last child path
// If the path exist, it will update data
func (z *Client) CreateTempWithValue(basePath string, value []byte) error {
	var (
		err     error
		tmpPath string
	)

	conn := z.getConn()
	if conn == nil {
		return ErrNilZkClientConn
	}

	if !strings.HasPrefix(basePath, string(os.PathSeparator)) {
		basePath = string(os.PathSeparator) + basePath
	}
	pathSlice := strings.Split(basePath, string(os.PathSeparator))[1:]
	length := len(pathSlice)
	for i, str := range pathSlice {
		tmpPath = path.Join(tmpPath, string(os.PathSeparator), str)
		// last child need be ephemeral
		if i == length-1 {
			_, err = conn.Create(tmpPath, value, zk.FlagEphemeral, zk.WorldACL(zk.PermAll))
			if err != nil {
				return errors.WithMessagef(err, "Error while invoking zk.Create(path:%s), the reason maybe is: ", tmpPath)
			}
			break
		}
		// we need ignore node exists error for those parent node
		_, err = conn.Create(tmpPath, []byte{}, 0, zk.WorldACL(zk.PermAll))
		if err != nil && !errors.Is(err, zk.ErrNodeExists) {
			return errors.WithMessagef(err, "Error while invoking zk.Create(path:%s), the reason maybe is: ", tmpPath)
		}
	}

	return nil
}

// Delete will delete basePath
func (z *Client) Delete(basePath string) error {
	conn := z.getConn()
	if conn == nil {
		return ErrNilZkClientConn
	}
	return errors.WithMessagef(conn.Delete(basePath, -1), "Delete(basePath:%s)", basePath)
}

// RegisterTemp registers temporary node by @basePath and @node
func (z *Client) RegisterTemp(basePath string, node string) (string, error) {
	zkPath := path.Join(basePath) + string(os.PathSeparator) + node
	conn := z.getConn()
	if conn == nil {
		return "", ErrNilZkClientConn
	}
	tmpPath, err := conn.Create(zkPath, []byte(""), zk.FlagEphemeral, zk.WorldACL(zk.PermAll))

	if err != nil {
		return zkPath, errors.WithStack(err)
	}

	return tmpPath, nil
}

// RegisterTempSeq register temporary sequence node by @basePath and @data
func (z *Client) RegisterTempSeq(basePath string, data []byte) (string, error) {
	var (
		err     error
		tmpPath string
	)

	err = ErrNilZkClientConn
	conn := z.getConn()
	if conn != nil {
		tmpPath, err = conn.Create(
			path.Join(basePath)+string(os.PathSeparator),
			data,
			zk.FlagEphemeral|zk.FlagSequence,
			zk.WorldACL(zk.PermAll),
		)
	}
	if err != nil && !errors.Is(err, zk.ErrNodeExists) {
		return "", errors.WithStack(err)
	}
	return tmpPath, nil
}

// GetChildrenW gets children watch by @path
func (z *Client) GetChildrenW(path string) ([]string, <-chan zk.Event, error) {
	conn := z.getConn()
	if conn == nil {
		return nil, nil, ErrNilZkClientConn
	}
	children, stat, watcher, err := conn.ChildrenW(path)

	if err != nil {
		return nil, nil, errors.WithMessagef(err, "Error while invoking zk.ChildrenW(path:%s), the reason maybe is: ", path)
	}
	if stat == nil {
		return nil, nil, errors.WithMessagef(ErrStatIsNil, "Error while invokeing zk.ChildrenW(path:%s), the reason is: ", path)
	}

	return children, watcher.EvtCh, nil
}

// GetChildren gets children by @path
func (z *Client) GetChildren(path string) ([]string, error) {
	conn := z.getConn()
	if conn == nil {
		return nil, ErrNilZkClientConn
	}
	children, stat, err := conn.Children(path)

	if err != nil {
		return nil, errors.WithMessagef(err, "Error while invoking zk.Children(path:%s), the reason maybe is: ", path)
	}
	if stat == nil {
		return nil, errors.Errorf("Error while invokeing zk.Children(path:%s), the reason is that the stat is nil", path)
	}

	return children, nil
}

// ExistW to judge watch whether it exists or not by @zkPath
func (z *Client) ExistW(zkPath string) (<-chan zk.Event, error) {
	conn := z.getConn()
	if conn == nil {
		return nil, ErrNilZkClientConn
	}
	_, _, watcher, err := conn.ExistsW(zkPath)

	if err != nil {
		return nil, errors.WithMessagef(err, "zk.ExistsW(path:%s)", zkPath)
	}

	return watcher.EvtCh, nil
}

// GetContent gets content by @zkPath
func (z *Client) GetContent(zkPath string) ([]byte, *zk.Stat, error) {
	return z.Conn.Get(zkPath)
}

// SetContent set content of zkPath
func (z *Client) SetContent(zkPath string, content []byte, version int32) (*zk.Stat, error) {
	return z.Conn.Set(zkPath, content, version)
}

// getConn gets zookeeper connection safely
func (z *Client) getConn() *zk.Conn {
	if z == nil {
		return nil
	}
	z.RLock()
	defer z.RUnlock()
	return z.Conn
}

// Reconnect gets zookeeper reconnect event
func (z *Client) Reconnect() <-chan struct{} {
	return z.reconnectCh
}

// GetEventHandler gets zookeeper event handler
func (z *Client) GetEventHandler() EventHandler {
	return z.zkEventHandler
}

func (z *Client) Close() {
	if z.share {
		zkClientPool.Lock()
		defer zkClientPool.Unlock()
		z.activeNumber--
		if z.activeNumber == 0 {
			z.Conn.Close()
			delete(zkClientPool.zkClient, z.name)
		}
	} else {
		z.Lock()
		conn := z.Conn
		z.activeNumber--
		z.Conn = nil
		z.Unlock()
		if conn != nil {
			conn.Close()
		}
	}
}

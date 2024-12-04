package kv

import (
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"dubbo.apache.org/dubbo-go/v3/common"
	"dubbo.apache.org/dubbo-go/v3/common/constant"
	"github.com/dubbogo/go-zookeeper/zk"
	"github.com/pkg/errors"
	uatomic "go.uber.org/atomic"
)

const (
	ConnDelay    = 3 // connection delay interval
	MaxFailTimes = 3 // max fail times
)

var defaultTTL = 10 * time.Minute

// nolint
type ZkEventListener struct {
	Client      *ZookeeperClient
	pathMapLock sync.Mutex
	pathMap     map[string]*uatomic.Int32
	wg          sync.WaitGroup
	exit        chan struct{}
}

// NewZkEventListener returns a EventListener instance
func NewZkEventListener(client *ZookeeperClient) *ZkEventListener {
	return &ZkEventListener{
		Client:  client,
		pathMap: make(map[string]*uatomic.Int32),
		exit:    make(chan struct{}),
	}
}

// ListenServiceNodeEvent listen a path node event
func (l *ZkEventListener) ListenServiceNodeEvent(zkPath string, listener DataListener) {
	l.wg.Add(1)
	go func(zkPath string, listener DataListener) {
		defer l.wg.Done()
		if l.listenServiceNodeEvent(zkPath, listener) {
			listener.DataChange(Event{Path: zkPath, Action: EventTypeDel})
		}
		l.pathMapLock.Lock()
		delete(l.pathMap, zkPath)
		l.pathMapLock.Unlock()
		log.Warn().Msgf("ListenServiceNodeEvent->listenSelf(zk path{%s}) goroutine exit now", zkPath)
	}(zkPath, listener)
}

// ListenConfigurationEvent listen a path node event
func (l *ZkEventListener) ListenConfigurationEvent(zkPath string, listener DataListener) {
	l.wg.Add(1)
	go func(zkPath string, listener DataListener) {
		var eventChan = make(chan zk.Event, 16)
		l.Client.RegisterEvent(zkPath, eventChan)
		for {
			select {
			case event := <-eventChan:
				log.Info().Msgf("[ZkEventListener]Receive configuration change event:%#v", event)
				if event.Type == zk.EventNodeChildrenChanged || event.Type == zk.EventNotWatching {
					continue
				}
				// 1. Re-set watcher for the zk node
				_, _, _, err := l.Client.Conn.ExistsW(event.Path)
				if err != nil {
					log.Warn().Msgf("[ZkEventListener]Re-set watcher error, the reason is %+v", err)
					continue
				}

				action := EventTypeAdd
				var content string
				if event.Type == zk.EventNodeDeleted {
					action = EventTypeDel
				} else {
					// 2. Try to get new configuration value of the zk node
					// Notice: The order of step 1 and step 2 cannot be swapped, if you get value(with timestamp t1)
					// before re-set the watcher(with timestamp t2), and some one change the data of the zk node after
					// t2 but before t1, you may get the old value, and the new value will not trigger the event.
					contentBytes, _, err := l.Client.Conn.Get(event.Path)
					if err != nil {
						log.Warn().Msgf("[ListenConfigurationEvent]Get config value error, the reason is %+v", err)
						continue
					}
					content = string(contentBytes)
					log.Debug().Msgf("[ZkEventListener]Successfully get new config value: %s", string(content))
				}

				listener.DataChange(Event{
					Path:    event.Path,
					Action:  EventType(action),
					Content: content,
				})
			case <-l.exit:
				return
			}
		}
	}(zkPath, listener)
}

// nolint
func (l *ZkEventListener) listenServiceNodeEvent(zkPath string, listener ...DataListener) bool {
	l.pathMapLock.Lock()
	a, ok := l.pathMap[zkPath]
	if !ok || a.Load() > 1 {
		l.pathMapLock.Unlock()
		return false
	}
	a.Inc()
	l.pathMapLock.Unlock()
	defer a.Dec()
	var zkEvent zk.Event
	for {
		keyEventCh, err := l.Client.ExistW(zkPath)
		if err != nil {
			log.Warn().Msgf("existW{key:%s} = error{%v}", zkPath, err)
			return false
		}
		select {
		case zkEvent = <-keyEventCh:
			log.Warn().Msgf("get a zookeeper keyEventCh{type:%s, server:%s, path:%s, state:%d-%s, err:%s}",
				zkEvent.Type.String(), zkEvent.Server, zkEvent.Path, zkEvent.State, StateToString(zkEvent.State), zkEvent.Err)
			switch zkEvent.Type {
			case zk.EventNodeDataChanged:
				log.Warn().Msgf("zk.ExistW(key{%s}) = event{EventNodeDataChanged}", zkPath)
				if len(listener) > 0 {
					content, _, err := l.Client.Conn.Get(zkEvent.Path)
					if err != nil {
						log.Warn().Msgf("zk.Conn.Get{key:%s} = error{%v}", zkPath, err)
						return false
					}
					listener[0].DataChange(Event{Path: zkEvent.Path, Action: EventTypeUpdate, Content: string(content)})
				}
			case zk.EventNodeCreated:
				log.Warn().Msgf("[ZkEventListener][listenServiceNodeEvent]Get a EventNodeCreated event for path {%s}", zkPath)
				if len(listener) > 0 {
					content, _, err := l.Client.Conn.Get(zkEvent.Path)
					if err != nil {
						log.Warn().Msgf("zk.Conn.Get{key:%s} = error{%v}", zkPath, err)
						return false
					}
					listener[0].DataChange(Event{Path: zkEvent.Path, Action: EventTypeAdd, Content: string(content)})
				}
			case zk.EventNotWatching:
				log.Info().Msgf("[ZkEventListener][listenServiceNodeEvent]Get a EventNotWatching event for path {%s}", zkPath)
			case zk.EventNodeDeleted:
				log.Info().Msgf("[ZkEventListener][listenServiceNodeEvent]Get a EventNodeDeleted event for path {%s}", zkPath)
				return true
			}
		case <-l.exit:
			return false
		}
	}
}

func (l *ZkEventListener) handleZkNodeEvent(zkPath string, children []string, listener DataListener) {
	contains := func(s []string, e string) bool {
		for _, a := range s {
			if a == e {
				return true
			}
		}
		return false
	}
	newChildren, err := l.Client.GetChildren(zkPath)
	if err != nil {
		log.Error().Msgf("[ZkEventListener handleZkNodeEvent]Path{%s} child nodes changed, zk.Children() = error{%v}", zkPath, errors.WithStack(err))
		return
	}
	// a node was added -- listen the new node
	var (
		newNode string
	)
	for _, n := range newChildren {
		newNode = path.Join(zkPath, n)
		log.Debug().Msgf("[Zookeeper Listener] add zkNode{%s}", newNode)
		content, _, connErr := l.Client.Conn.Get(newNode)
		if connErr != nil {
			log.Error().Msgf("Get new node path {%v} 's content error,message is  {%v}",
				newNode, errors.WithStack(connErr))
		}
		if !listener.DataChange(Event{Path: newNode, Action: EventTypeAdd, Content: string(content)}) {
			continue
		}
		// listen l service node
		l.wg.Add(1)
		go func(node string, listener DataListener) {
			defer l.wg.Done()
			if l.listenServiceNodeEvent(node, listener) {
				log.Warn().Msgf("delete zkNode{%s}", node)
				listener.DataChange(Event{Path: node, Action: EventTypeDel})
			}
			l.pathMapLock.Lock()
			delete(l.pathMap, zkPath)
			l.pathMapLock.Unlock()
			log.Debug().Msgf("handleZkNodeEvent->listenSelf(zk path{%s}) goroutine exit now", node)
		}(newNode, listener)
	}

	// old node was deleted
	var oldNode string
	for _, n := range children {
		if contains(newChildren, n) {
			continue
		}
		oldNode = path.Join(zkPath, n)
		log.Warn().Msgf("delete oldNode{%s}", oldNode)
		listener.DataChange(Event{Path: oldNode, Action: EventTypeDel})
	}
}

// listenerAllDirEvents listens all services when conf.InterfaceKey = "*"
func (l *ZkEventListener) listenAllDirEvents(conf *common.URL, listener DataListener) {
	var (
		failTimes int
		ttl       time.Duration
	)
	ttl = defaultTTL
	if conf != nil {
		if timeout, err := time.ParseDuration(conf.GetParam(constant.RegistryTTLKey, constant.DefaultRegTTL)); err == nil {
			ttl = timeout
		} else {
			log.Warn().Msgf("[Zookeeper EventListener][listenDirEvent] Wrong configuration for registry.ttl, error=%+v, using default value %v instead", err, defaultTTL)
		}
	}
	if ttl > 20e9 {
		ttl = 20e9
	}

	rootPath := path.Join(constant.PathSeparator, constant.Dubbo)
	for {
		// get all interfaces
		children, childEventCh, err := l.Client.GetChildrenW(rootPath)
		if err != nil {
			failTimes++
			if MaxFailTimes <= failTimes {
				failTimes = MaxFailTimes
			}
			log.Error().Msgf("[Zookeeper EventListener][listenDirEvent] Get children of path {%s} with watcher failed, the error is %+v", rootPath, err)
			// Maybe the zookeeper does not ready yet, sleep failTimes * ConnDelay senconds to wait
			after := time.After(timeSecondDuration(failTimes * ConnDelay))
			select {
			case <-after:
				continue
			case <-l.exit:
				return
			}
		}
		failTimes = 0
		if len(children) == 0 {
			log.Warn().Msgf("[Zookeeper EventListener][listenDirEvent] Can not get any children for the path \"%s\", please check if the provider does ready.", rootPath)
		}
		for _, c := range children {
			// Build the child path
			zkRootPath := path.Join(rootPath, constant.PathSeparator, url.QueryEscape(c), constant.PathSeparator, constant.ProvidersCategory)
			// Save the path to avoid listen repeatedly
			l.pathMapLock.Lock()
			if _, ok := l.pathMap[zkRootPath]; ok {
				log.Warn().Msgf("[Zookeeper EventListener][listenDirEvent] The child with zk path {%s} has already been listened.", zkRootPath)
				l.pathMapLock.Unlock()
				continue
			} else {
				l.pathMap[zkRootPath] = uatomic.NewInt32(0)
			}
			l.pathMapLock.Unlock()
			log.Debug().Msgf("[Zookeeper EventListener][listenDirEvent] listen dubbo interface key{%s}", zkRootPath)
			l.wg.Add(1)
			// listen every interface
			go l.listenDirEvent(conf, zkRootPath, listener, c)
		}

		ticker := time.NewTicker(ttl)
		select {
		case <-ticker.C:
			ticker.Stop()
		case zkEvent := <-childEventCh:
			log.Debug().Msgf("Get a zookeeper childEventCh{type:%s, server:%s, path:%s, state:%d-%s, err:%v}",
				zkEvent.Type.String(), zkEvent.Server, zkEvent.Path, zkEvent.State, StateToString(zkEvent.State), zkEvent.Err)
			ticker.Stop()
		case <-l.exit:
			log.Warn().Msgf("listen(path{%s}) goroutine exit now...", rootPath)
			ticker.Stop()
			return
		}
	}
}

func (l *ZkEventListener) listenDirEvent(conf *common.URL, zkRootPath string, listener DataListener, intf string) {
	defer l.wg.Done()
	if intf == constant.AnyValue {
		l.listenAllDirEvents(conf, listener)
		return
	}
	var (
		failTimes int
		ttl       time.Duration
	)
	ttl = defaultTTL
	if conf != nil {
		timeout, err := time.ParseDuration(conf.GetParam(constant.RegistryTTLKey, constant.DefaultRegTTL))
		if err == nil {
			ttl = timeout
		} else {
			log.Warn().Msgf("[Zookeeper EventListener][listenDirEvent] Wrong configuration for registry.ttl, error=%+v, using default value %v instead", err, defaultTTL)
		}
	}
	for {
		// Get current children with watcher for the zkRootPath
		children, childEventCh, err := l.Client.GetChildrenW(zkRootPath)
		if err != nil {
			failTimes++
			if MaxFailTimes <= failTimes {
				failTimes = MaxFailTimes
			}

			if !errors.Is(err, zk.ErrNoNode) { // ignore if node not exist
				log.Error().Msgf("[Zookeeper EventListener][listenDirEvent] Get children of path {%s} with watcher failed, the error is %+v", zkRootPath, err)
			}
			// Maybe the provider does not ready yet, sleep failTimes * ConnDelay senconds to wait
			after := time.After(timeSecondDuration(failTimes * ConnDelay))
			select {
			case <-after:
				continue
			case <-l.exit:
				return
			}
		}
		failTimes = 0
		if len(children) == 0 {
			log.Debug().Msgf("[Zookeeper EventListener][listenDirEvent] Can not gey any children for the path {%s}, please check if the provider does ready.", zkRootPath)
		}
		for _, c := range children {
			// Only need to compare Path when subscribing to provider
			if strings.LastIndex(zkRootPath, constant.ProviderCategory) != -1 {
				provider, _ := common.NewURL(c)
				if provider.Interface() != intf || !common.IsAnyCondition(constant.AnyValue, conf.Group(), conf.Version(), provider) {
					continue
				}
			}
			// Build the children path
			zkNodePath := path.Join(zkRootPath, c)
			// Save the path to avoid listen repeatedly
			l.pathMapLock.Lock()
			_, ok := l.pathMap[zkNodePath]
			if !ok {
				l.pathMap[zkNodePath] = uatomic.NewInt32(0)
			}
			l.pathMapLock.Unlock()
			if ok {
				log.Warn().Msgf("[Zookeeper EventListener][listenDirEvent] The child with zk path {%s} has already been listened.", zkNodePath)
				l.Client.RLock()
				if l.Client.Conn == nil {
					l.Client.RUnlock()
					break
				}
				content, _, err := l.Client.Conn.Get(zkNodePath)
				l.Client.RUnlock()
				if err != nil {
					log.Error().Msgf("[Zookeeper EventListener][listenDirEvent] Get content of the child node {%v} failed, the error is %+v", zkNodePath, errors.WithStack(err))
				}
				listener.DataChange(Event{Path: zkNodePath, Action: EventTypeAdd, Content: string(content)})
				continue
			}
			// When Zk disconnected, the Conn will be set to nil, so here need check the value of Conn
			l.Client.RLock()
			if l.Client.Conn == nil {
				l.Client.RUnlock()
				break
			}
			content, _, err := l.Client.Conn.Get(zkNodePath)
			l.Client.RUnlock()
			if err != nil {
				log.Error().Msgf("[Zookeeper EventListener][listenDirEvent] Get content of the child node {%v} failed, the error is %+v", zkNodePath, errors.WithStack(err))
			}
			log.Debug().Msgf("[Zookeeper EventListener][listenDirEvent] Get children!{%s}", zkNodePath)
			if !listener.DataChange(Event{Path: zkNodePath, Action: EventTypeAdd, Content: string(content)}) {
				continue
			}
			log.Debug().Msgf("[Zookeeper EventListener][listenDirEvent] listen dubbo service key{%s}", zkNodePath)
			l.wg.Add(1)
			go func(zkPath string, listener DataListener) {
				defer l.wg.Done()
				if l.listenServiceNodeEvent(zkPath, listener) {
					listener.DataChange(Event{Path: zkPath, Action: EventTypeDel})
				}
				l.pathMapLock.Lock()
				delete(l.pathMap, zkPath)
				l.pathMapLock.Unlock()
				log.Warn().Msgf("listenDirEvent->listenSelf(zk path{%s}) goroutine exit now", zkPath)
			}(zkNodePath, listener)
		}
		if l.startScheduleWatchTask(zkRootPath, children, ttl, listener, childEventCh) {
			return
		}
	}
}

// startScheduleWatchTask periodically update provider information, return true when receive exit signal
func (l *ZkEventListener) startScheduleWatchTask(
	zkRootPath string, children []string, ttl time.Duration,
	listener DataListener, childEventCh <-chan zk.Event) bool {
	tickerTTL := ttl
	if tickerTTL > 20e9 {
		tickerTTL = 20e9
	}
	ticker := time.NewTicker(tickerTTL)
	for {
		select {
		case <-ticker.C:
			l.handleZkNodeEvent(zkRootPath, children, listener)
			if tickerTTL < ttl {
				tickerTTL *= 2
				if tickerTTL > ttl {
					tickerTTL = ttl
				}
				ticker.Stop()
				ticker = time.NewTicker(tickerTTL)
			}
		case zkEvent := <-childEventCh:
			log.Debug().Msgf("Get a zookeeper childEventCh{type:%s, server:%s, path:%s, state:%d-%s, err:%v}",
				zkEvent.Type.String(), zkEvent.Server, zkEvent.Path, zkEvent.State, StateToString(zkEvent.State), zkEvent.Err)
			ticker.Stop()
			if zkEvent.Type == zk.EventNodeChildrenChanged {
				l.handleZkNodeEvent(zkEvent.Path, children, listener)
			}
			return false
		case <-l.exit:
			log.Warn().Msgf("listen(path{%s}) goroutine exit now...", zkRootPath)
			ticker.Stop()
			return true
		}
	}
}

func timeSecondDuration(sec int) time.Duration {
	return time.Duration(sec) * time.Second
}

// ListenServiceEvent is invoked by ZkConsumerRegistry::Register/ZkConsumerRegistry::get/ZkConsumerRegistry::getListener
// registry.go:Listen -> listenServiceEvent -> listenDirEvent -> listenServiceNodeEvent
// registry.go:Listen -> listenServiceEvent -> listenServiceNodeEvent
func (l *ZkEventListener) ListenServiceEvent(conf *common.URL, zkPath string, listener DataListener) {
	log.Info().Msgf("[Zookeeper Listener] listen dubbo path{%s}", zkPath)
	l.wg.Add(1)
	go func(zkPath string, listener DataListener) {
		intf := ""
		if conf != nil {
			intf = conf.Interface()
		}
		l.listenDirEvent(conf, zkPath, listener, intf)
		log.Warn().Msgf("ListenServiceEvent->listenDirEvent(zkPath{%s}) goroutine exit now", zkPath)
	}(zkPath, listener)
}

// Close will let client listen exit
func (l *ZkEventListener) Close() {
	close(l.exit)
	l.wg.Wait()
}

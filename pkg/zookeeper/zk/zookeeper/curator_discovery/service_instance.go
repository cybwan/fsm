package curator_discovery

// ServiceInstance which define in curator-x-discovery, please refer to
// https://github.com/apache/curator/blob/master/curator-x-discovery/src/main/java/org/apache/curator/x/discovery/ServiceInstance.java
type ServiceInstance struct {
	Name                string      `json:"name,omitempty"`
	ID                  string      `json:"id,omitempty"`
	Address             string      `json:"address,omitempty"`
	Port                int         `json:"port,omitempty"`
	Payload             interface{} `json:"payload,omitempty"`
	RegistrationTimeUTC int64       `json:"registrationTimeUTC,omitempty"`
	Tag                 string      `json:"tag,omitempty"`
}

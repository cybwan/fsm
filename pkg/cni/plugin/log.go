package plugin

import "os"

func SetLogFile(file string) {
	if logfile, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		log = log.Output(logfile)
	}
}

/*
 * MIT License
 *
 * Copyright (c) since 2021,  flomesh.io Authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package repo

import (
	"strings"

	"github.com/flomesh-io/fsm/pkg/logger"
)

type Codebase struct {
	Version     int64    `json:"version,string,omitempty"`
	Path        string   `json:"path,omitempty"`
	Main        string   `json:"main,omitempty"`
	Base        string   `json:"base,omitempty"`
	Files       []string `json:"files,omitempty"`
	EditFiles   []string `json:"editFiles,omitempty"`
	ErasedFiles []string `json:"erasedFiles,omitempty"`
	Derived     []string `json:"derived,omitempty"`
}

type Batch struct {
	Basepath string
	Items    []BatchItem
	DelItems []string
}

type BatchItem struct {
	Path     string
	Filename string
	Content  interface{}
}

func (item *BatchItem) String() string {
	path := item.Path

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	if path == "/" {
		return "/" + item.Filename
	}

	return path + "/" + item.Filename
}

var log = logger.New("pipy-repo-client")

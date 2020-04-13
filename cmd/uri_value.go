package cmd

import (
	"fmt"
	"net/url"
	"strings"
)

type uriSliceValue struct {
	urls    *[]*url.URL
	changed bool
}

func newURISliceValue(urls *[]*url.URL) *uriSliceValue {
	return &uriSliceValue{
		urls: urls,
	}
}

func (us *uriSliceValue) Type() string {
	return "uris"
}

func (us *uriSliceValue) String() string {
	return fmt.Sprintf("%s", *us.urls)
}

func (us *uriSliceValue) Set(urlRawStr string) error {
	urlStrList := strings.Split(urlRawStr, ",")
	var urls []*url.URL
	for _, urlStr := range urlStrList {
		u, err := url.Parse(urlStr)
		if err != nil {
			return err
		}
		urls = append(urls, u)
	}

	// overwrite the defaults/initial value on first Set
	if us.changed {
		*us.urls = append(*us.urls, urls...)
	} else {
		*us.urls = urls
		us.changed = true
	}

	return nil
}

// Code generated by go-swagger; DO NOT EDIT.

package ipam

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"errors"
	"net/url"
	golangswaggerpaths "path"
	"strings"
)

// PostIPAMIPURL generates an URL for the post IP a m IP operation
type PostIPAMIPURL struct {
	IP string

	_basePath string
	// avoid unkeyed usage
	_ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *PostIPAMIPURL) WithBasePath(bp string) *PostIPAMIPURL {
	o.SetBasePath(bp)
	return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *PostIPAMIPURL) SetBasePath(bp string) {
	o._basePath = bp
}

// Build a url path and query string
func (o *PostIPAMIPURL) Build() (*url.URL, error) {
	var result url.URL

	var _path = "/ipam/{ip}"

	ip := o.IP
	if ip != "" {
		_path = strings.Replace(_path, "{ip}", ip, -1)
	} else {
		return nil, errors.New("IP is required on PostIPAMIPURL")
	}
	_basePath := o._basePath
	if _basePath == "" {
		_basePath = "/v1beta"
	}
	result.Path = golangswaggerpaths.Join(_basePath, _path)

	return &result, nil
}

// Must is a helper function to panic when the url builder returns an error
func (o *PostIPAMIPURL) Must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	if u == nil {
		panic("url can't be nil")
	}
	return u
}

// String returns the string representation of the path with query string
func (o *PostIPAMIPURL) String() string {
	return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *PostIPAMIPURL) BuildFull(scheme, host string) (*url.URL, error) {
	if scheme == "" {
		return nil, errors.New("scheme is required for a full url on PostIPAMIPURL")
	}
	if host == "" {
		return nil, errors.New("host is required for a full url on PostIPAMIPURL")
	}

	base, err := o.Build()
	if err != nil {
		return nil, err
	}

	base.Scheme = scheme
	base.Host = host
	return base, nil
}

// StringFull returns the string representation of a complete url
func (o *PostIPAMIPURL) StringFull(scheme, host string) string {
	return o.Must(o.BuildFull(scheme, host)).String()
}
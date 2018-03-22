// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file was automatically generated by lister-gen

package v1

import (
	v1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// CiliumNetworkPolicyLister helps list CiliumNetworkPolicies.
type CiliumNetworkPolicyLister interface {
	// List lists all CiliumNetworkPolicies in the indexer.
	List(selector labels.Selector) (ret []*v1.CiliumNetworkPolicy, err error)
	// CiliumNetworkPolicies returns an object that can list and get CiliumNetworkPolicies.
	CiliumNetworkPolicies(namespace string) CiliumNetworkPolicyNamespaceLister
	CiliumNetworkPolicyListerExpansion
}

// ciliumNetworkPolicyLister implements the CiliumNetworkPolicyLister interface.
type ciliumNetworkPolicyLister struct {
	indexer cache.Indexer
}

// NewCiliumNetworkPolicyLister returns a new CiliumNetworkPolicyLister.
func NewCiliumNetworkPolicyLister(indexer cache.Indexer) CiliumNetworkPolicyLister {
	return &ciliumNetworkPolicyLister{indexer: indexer}
}

// List lists all CiliumNetworkPolicies in the indexer.
func (s *ciliumNetworkPolicyLister) List(selector labels.Selector) (ret []*v1.CiliumNetworkPolicy, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.CiliumNetworkPolicy))
	})
	return ret, err
}

// CiliumNetworkPolicies returns an object that can list and get CiliumNetworkPolicies.
func (s *ciliumNetworkPolicyLister) CiliumNetworkPolicies(namespace string) CiliumNetworkPolicyNamespaceLister {
	return ciliumNetworkPolicyNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// CiliumNetworkPolicyNamespaceLister helps list and get CiliumNetworkPolicies.
type CiliumNetworkPolicyNamespaceLister interface {
	// List lists all CiliumNetworkPolicies in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1.CiliumNetworkPolicy, err error)
	// Get retrieves the CiliumNetworkPolicy from the indexer for a given namespace and name.
	Get(name string) (*v1.CiliumNetworkPolicy, error)
	CiliumNetworkPolicyNamespaceListerExpansion
}

// ciliumNetworkPolicyNamespaceLister implements the CiliumNetworkPolicyNamespaceLister
// interface.
type ciliumNetworkPolicyNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all CiliumNetworkPolicies in the indexer for a given namespace.
func (s ciliumNetworkPolicyNamespaceLister) List(selector labels.Selector) (ret []*v1.CiliumNetworkPolicy, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.CiliumNetworkPolicy))
	})
	return ret, err
}

// Get retrieves the CiliumNetworkPolicy from the indexer for a given namespace and name.
func (s ciliumNetworkPolicyNamespaceLister) Get(name string) (*v1.CiliumNetworkPolicy, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("ciliumnetworkpolicy"), name)
	}
	return obj.(*v1.CiliumNetworkPolicy), nil
}

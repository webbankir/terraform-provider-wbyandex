// Code generated by sdkgen. DO NOT EDIT.

//nolint
package iam

import (
	"context"

	"google.golang.org/grpc"

	iam "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
)

//revive:disable

// ApiKeyServiceClient is a iam.ApiKeyServiceClient with
// lazy GRPC connection initialization.
type ApiKeyServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// Create implements iam.ApiKeyServiceClient
func (c *ApiKeyServiceClient) Create(ctx context.Context, in *iam.CreateApiKeyRequest, opts ...grpc.CallOption) (*iam.CreateApiKeyResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return iam.NewApiKeyServiceClient(conn).Create(ctx, in, opts...)
}

// Delete implements iam.ApiKeyServiceClient
func (c *ApiKeyServiceClient) Delete(ctx context.Context, in *iam.DeleteApiKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return iam.NewApiKeyServiceClient(conn).Delete(ctx, in, opts...)
}

// Get implements iam.ApiKeyServiceClient
func (c *ApiKeyServiceClient) Get(ctx context.Context, in *iam.GetApiKeyRequest, opts ...grpc.CallOption) (*iam.ApiKey, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return iam.NewApiKeyServiceClient(conn).Get(ctx, in, opts...)
}

// List implements iam.ApiKeyServiceClient
func (c *ApiKeyServiceClient) List(ctx context.Context, in *iam.ListApiKeysRequest, opts ...grpc.CallOption) (*iam.ListApiKeysResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return iam.NewApiKeyServiceClient(conn).List(ctx, in, opts...)
}

type ApiKeyIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *ApiKeyServiceClient
	request *iam.ListApiKeysRequest

	items []*iam.ApiKey
}

func (c *ApiKeyServiceClient) ApiKeyIterator(ctx context.Context, req *iam.ListApiKeysRequest, opts ...grpc.CallOption) *ApiKeyIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &ApiKeyIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *ApiKeyIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started && it.request.PageToken == "" {
		return false
	}
	it.started = true

	if it.requestedSize == 0 || it.requestedSize > it.pageSize {
		it.request.PageSize = it.pageSize
	} else {
		it.request.PageSize = it.requestedSize
	}

	response, err := it.client.List(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.ApiKeys
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *ApiKeyIterator) Take(size int64) ([]*iam.ApiKey, error) {
	if it.err != nil {
		return nil, it.err
	}

	if size == 0 {
		size = 1 << 32 // something insanely large
	}
	it.requestedSize = size
	defer func() {
		// reset iterator for future calls.
		it.requestedSize = 0
	}()

	var result []*iam.ApiKey

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *ApiKeyIterator) TakeAll() ([]*iam.ApiKey, error) {
	return it.Take(0)
}

func (it *ApiKeyIterator) Value() *iam.ApiKey {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *ApiKeyIterator) Error() error {
	return it.err
}

// ListOperations implements iam.ApiKeyServiceClient
func (c *ApiKeyServiceClient) ListOperations(ctx context.Context, in *iam.ListApiKeyOperationsRequest, opts ...grpc.CallOption) (*iam.ListApiKeyOperationsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return iam.NewApiKeyServiceClient(conn).ListOperations(ctx, in, opts...)
}

type ApiKeyOperationsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *ApiKeyServiceClient
	request *iam.ListApiKeyOperationsRequest

	items []*operation.Operation
}

func (c *ApiKeyServiceClient) ApiKeyOperationsIterator(ctx context.Context, req *iam.ListApiKeyOperationsRequest, opts ...grpc.CallOption) *ApiKeyOperationsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &ApiKeyOperationsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *ApiKeyOperationsIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started && it.request.PageToken == "" {
		return false
	}
	it.started = true

	if it.requestedSize == 0 || it.requestedSize > it.pageSize {
		it.request.PageSize = it.pageSize
	} else {
		it.request.PageSize = it.requestedSize
	}

	response, err := it.client.ListOperations(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Operations
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *ApiKeyOperationsIterator) Take(size int64) ([]*operation.Operation, error) {
	if it.err != nil {
		return nil, it.err
	}

	if size == 0 {
		size = 1 << 32 // something insanely large
	}
	it.requestedSize = size
	defer func() {
		// reset iterator for future calls.
		it.requestedSize = 0
	}()

	var result []*operation.Operation

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *ApiKeyOperationsIterator) TakeAll() ([]*operation.Operation, error) {
	return it.Take(0)
}

func (it *ApiKeyOperationsIterator) Value() *operation.Operation {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *ApiKeyOperationsIterator) Error() error {
	return it.err
}

// Update implements iam.ApiKeyServiceClient
func (c *ApiKeyServiceClient) Update(ctx context.Context, in *iam.UpdateApiKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return iam.NewApiKeyServiceClient(conn).Update(ctx, in, opts...)
}
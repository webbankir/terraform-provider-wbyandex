// Code generated by sdkgen. DO NOT EDIT.

//nolint
package certificatemanager

import (
	"context"

	"google.golang.org/grpc"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/access"
	certificatemanager "github.com/yandex-cloud/go-genproto/yandex/cloud/certificatemanager/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
)

//revive:disable

// CertificateServiceClient is a certificatemanager.CertificateServiceClient with
// lazy GRPC connection initialization.
type CertificateServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// Create implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) Create(ctx context.Context, in *certificatemanager.CreateCertificateRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).Create(ctx, in, opts...)
}

// Delete implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) Delete(ctx context.Context, in *certificatemanager.DeleteCertificateRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).Delete(ctx, in, opts...)
}

// Get implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) Get(ctx context.Context, in *certificatemanager.GetCertificateRequest, opts ...grpc.CallOption) (*certificatemanager.Certificate, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).Get(ctx, in, opts...)
}

// List implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) List(ctx context.Context, in *certificatemanager.ListCertificatesRequest, opts ...grpc.CallOption) (*certificatemanager.ListCertificatesResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).List(ctx, in, opts...)
}

type CertificateIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *CertificateServiceClient
	request *certificatemanager.ListCertificatesRequest

	items []*certificatemanager.Certificate
}

func (c *CertificateServiceClient) CertificateIterator(ctx context.Context, req *certificatemanager.ListCertificatesRequest, opts ...grpc.CallOption) *CertificateIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &CertificateIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *CertificateIterator) Next() bool {
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

	it.items = response.Certificates
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *CertificateIterator) Take(size int64) ([]*certificatemanager.Certificate, error) {
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

	var result []*certificatemanager.Certificate

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *CertificateIterator) TakeAll() ([]*certificatemanager.Certificate, error) {
	return it.Take(0)
}

func (it *CertificateIterator) Value() *certificatemanager.Certificate {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *CertificateIterator) Error() error {
	return it.err
}

// ListAccessBindings implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) ListAccessBindings(ctx context.Context, in *access.ListAccessBindingsRequest, opts ...grpc.CallOption) (*access.ListAccessBindingsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).ListAccessBindings(ctx, in, opts...)
}

type CertificateAccessBindingsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *CertificateServiceClient
	request *access.ListAccessBindingsRequest

	items []*access.AccessBinding
}

func (c *CertificateServiceClient) CertificateAccessBindingsIterator(ctx context.Context, req *access.ListAccessBindingsRequest, opts ...grpc.CallOption) *CertificateAccessBindingsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &CertificateAccessBindingsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *CertificateAccessBindingsIterator) Next() bool {
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

	response, err := it.client.ListAccessBindings(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.AccessBindings
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *CertificateAccessBindingsIterator) Take(size int64) ([]*access.AccessBinding, error) {
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

	var result []*access.AccessBinding

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *CertificateAccessBindingsIterator) TakeAll() ([]*access.AccessBinding, error) {
	return it.Take(0)
}

func (it *CertificateAccessBindingsIterator) Value() *access.AccessBinding {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *CertificateAccessBindingsIterator) Error() error {
	return it.err
}

// ListOperations implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) ListOperations(ctx context.Context, in *certificatemanager.ListCertificateOperationsRequest, opts ...grpc.CallOption) (*certificatemanager.ListCertificateOperationsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).ListOperations(ctx, in, opts...)
}

type CertificateOperationsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *CertificateServiceClient
	request *certificatemanager.ListCertificateOperationsRequest

	items []*operation.Operation
}

func (c *CertificateServiceClient) CertificateOperationsIterator(ctx context.Context, req *certificatemanager.ListCertificateOperationsRequest, opts ...grpc.CallOption) *CertificateOperationsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &CertificateOperationsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *CertificateOperationsIterator) Next() bool {
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

func (it *CertificateOperationsIterator) Take(size int64) ([]*operation.Operation, error) {
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

func (it *CertificateOperationsIterator) TakeAll() ([]*operation.Operation, error) {
	return it.Take(0)
}

func (it *CertificateOperationsIterator) Value() *operation.Operation {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *CertificateOperationsIterator) Error() error {
	return it.err
}

// RequestNew implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) RequestNew(ctx context.Context, in *certificatemanager.RequestNewCertificateRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).RequestNew(ctx, in, opts...)
}

// SetAccessBindings implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) SetAccessBindings(ctx context.Context, in *access.SetAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).SetAccessBindings(ctx, in, opts...)
}

// Update implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) Update(ctx context.Context, in *certificatemanager.UpdateCertificateRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).Update(ctx, in, opts...)
}

// UpdateAccessBindings implements certificatemanager.CertificateServiceClient
func (c *CertificateServiceClient) UpdateAccessBindings(ctx context.Context, in *access.UpdateAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return certificatemanager.NewCertificateServiceClient(conn).UpdateAccessBindings(ctx, in, opts...)
}
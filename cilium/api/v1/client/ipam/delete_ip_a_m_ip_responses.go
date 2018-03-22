// Code generated by go-swagger; DO NOT EDIT.

package ipam

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/api/v1/models"
)

// DeleteIPAMIPReader is a Reader for the DeleteIPAMIP structure.
type DeleteIPAMIPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteIPAMIPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewDeleteIPAMIPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewDeleteIPAMIPInvalid()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 404:
		result := NewDeleteIPAMIPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewDeleteIPAMIPFailure()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 501:
		result := NewDeleteIPAMIPDisabled()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeleteIPAMIPOK creates a DeleteIPAMIPOK with default headers values
func NewDeleteIPAMIPOK() *DeleteIPAMIPOK {
	return &DeleteIPAMIPOK{}
}

/*DeleteIPAMIPOK handles this case with default header values.

Success
*/
type DeleteIPAMIPOK struct {
}

func (o *DeleteIPAMIPOK) Error() string {
	return fmt.Sprintf("[DELETE /ipam/{ip}][%d] deleteIpAMIpOK ", 200)
}

func (o *DeleteIPAMIPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteIPAMIPInvalid creates a DeleteIPAMIPInvalid with default headers values
func NewDeleteIPAMIPInvalid() *DeleteIPAMIPInvalid {
	return &DeleteIPAMIPInvalid{}
}

/*DeleteIPAMIPInvalid handles this case with default header values.

Invalid IP address
*/
type DeleteIPAMIPInvalid struct {
}

func (o *DeleteIPAMIPInvalid) Error() string {
	return fmt.Sprintf("[DELETE /ipam/{ip}][%d] deleteIpAMIpInvalid ", 400)
}

func (o *DeleteIPAMIPInvalid) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteIPAMIPNotFound creates a DeleteIPAMIPNotFound with default headers values
func NewDeleteIPAMIPNotFound() *DeleteIPAMIPNotFound {
	return &DeleteIPAMIPNotFound{}
}

/*DeleteIPAMIPNotFound handles this case with default header values.

IP address not found
*/
type DeleteIPAMIPNotFound struct {
}

func (o *DeleteIPAMIPNotFound) Error() string {
	return fmt.Sprintf("[DELETE /ipam/{ip}][%d] deleteIpAMIpNotFound ", 404)
}

func (o *DeleteIPAMIPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteIPAMIPFailure creates a DeleteIPAMIPFailure with default headers values
func NewDeleteIPAMIPFailure() *DeleteIPAMIPFailure {
	return &DeleteIPAMIPFailure{}
}

/*DeleteIPAMIPFailure handles this case with default header values.

Address release failure
*/
type DeleteIPAMIPFailure struct {
	Payload models.Error
}

func (o *DeleteIPAMIPFailure) Error() string {
	return fmt.Sprintf("[DELETE /ipam/{ip}][%d] deleteIpAMIpFailure  %+v", 500, o.Payload)
}

func (o *DeleteIPAMIPFailure) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteIPAMIPDisabled creates a DeleteIPAMIPDisabled with default headers values
func NewDeleteIPAMIPDisabled() *DeleteIPAMIPDisabled {
	return &DeleteIPAMIPDisabled{}
}

/*DeleteIPAMIPDisabled handles this case with default header values.

Allocation for address family disabled
*/
type DeleteIPAMIPDisabled struct {
}

func (o *DeleteIPAMIPDisabled) Error() string {
	return fmt.Sprintf("[DELETE /ipam/{ip}][%d] deleteIpAMIpDisabled ", 501)
}

func (o *DeleteIPAMIPDisabled) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

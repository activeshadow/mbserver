// Package mbserver implments a Modbus server (slave).
package mbserver

import (
	"context"
	"io"
	"net"

	"github.com/goburrow/serial"
)

// FunctionHandler defines a function type for defining custom Modbus
// function code handlers.
type FunctionHandler func(*Server, Framer) ([]byte, *Exception)

// ContextFunctionHandler defines a function type for defining external Modbus
// function code handlers with a Context.
type ContextFunctionHandler func(context.Context, Framer) ([]byte, *Exception)

// Server is a Modbus slave with allocated memory for discrete inputs, coils, etc.
type Server struct {
	// Debug enables more verbose messaging.
	Debug            bool
	listeners        []net.Listener
	ports            []serial.Port
	requestChan      chan *Request
	function         [256]FunctionHandler
	DiscreteInputs   []byte
	Coils            []byte
	HoldingRegisters []uint16
	InputRegisters   []uint16

	handlers [256]ContextFunctionHandler
}

// Request contains the connection and Modbus frame.
type Request struct {
	ctx   context.Context
	conn  io.ReadWriteCloser
	frame Framer
}

// NewServer creates a new Modbus server (slave).
func NewServer() *Server {
	s := &Server{
		requestChan: make(chan *Request),
	}

	go s.handler()
	return s
}

// NewServer creates a new Modbus server (slave) with default function handlers
// and registers.
func NewServerWithDefaults() *Server {
	s := &Server{}

	// Allocate Modbus memory maps.
	s.DiscreteInputs = make([]byte, 65536)
	s.Coils = make([]byte, 65536)
	s.HoldingRegisters = make([]uint16, 65536)
	s.InputRegisters = make([]uint16, 65536)

	// Add default functions.
	s.function[1] = ReadCoils
	s.function[2] = ReadDiscreteInputs
	s.function[3] = ReadHoldingRegisters
	s.function[4] = ReadInputRegisters
	s.function[5] = WriteSingleCoil
	s.function[6] = WriteHoldingRegister
	s.function[15] = WriteMultipleCoils
	s.function[16] = WriteHoldingRegisters

	s.requestChan = make(chan *Request)
	go s.handler()

	return s
}

// RegisterFunctionHandler override the default behavior for a given Modbus function.
func (s *Server) RegisterFunctionHandler(code uint8, handler FunctionHandler) {
	s.function[code] = handler
}

// RegisterContextFunctionHandler registers a new external ContextFunctionHandler.
func (s *Server) RegisterContextFunctionHandler(code uint8, handler ContextFunctionHandler) {
	s.handlers[code] = handler
}

func (s *Server) handle(request *Request) Framer {
	var exception *Exception
	var data []byte

	response := request.frame.Copy()

	function := request.frame.GetFunction()
	if s.function[function] != nil {
		data, exception = s.function[function](s, request.frame)
		response.SetData(data)
	} else if s.handlers[function] != nil {
		data, exception = s.handlers[function](request.ctx, request.frame)
		response.SetData(data)
	} else {
		exception = &IllegalFunction
	}

	if exception != &Success {
		response.SetException(exception)
	}

	return response
}

// All requests are handled synchronously to prevent modbus memory corruption.
func (s *Server) handler() {
	for {
		request := <-s.requestChan
		response := s.handle(request)
		request.conn.Write(response.Bytes())
	}
}

// Close stops listening to TCP/IP ports and closes serial ports.
func (s *Server) Close() {
	for _, listen := range s.listeners {
		listen.Close()
	}
	for _, port := range s.ports {
		port.Close()
	}
}

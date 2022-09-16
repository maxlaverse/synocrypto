package encoding

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	leadByteValueInt    = 0x01
	leadByteValueString = 0x10
	leadByteValueBytes  = 0x11
	leadByteValueStop   = 0x40
	leadByteValueDict   = 0x42
)

func readObject(f io.Reader) (interface{}, error) {
	leadByte, err := readLeadByte(f)
	if err == io.EOF {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("error while reading next object lead byte: %w", err)
	}

	switch leadByte {
	case leadByteValueBytes:
		return readBytes(f)
	case leadByteValueDict:
		return readDict(f)
	case leadByteValueString:
		return readString(f)
	case leadByteValueInt:
		return readInt(f)
	case leadByteValueStop:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported type of lead byte '%v'", leadByte)
	}
}

func readLeadByte(f io.Reader) (byte, error) {
	buf := make([]byte, 1)
	_, err := f.Read(buf)
	if err != nil {
		return 0, err
	}
	return buf[0], nil
}

func readBytes(f io.Reader) ([]byte, error) {
	buf := make([]byte, 2)
	_, err := f.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading length of bytes field: %w", err)
	}

	length := binary.BigEndian.Uint16(buf)
	if length == 0 {
		return []byte{}, nil
	}

	buf = make([]byte, length)
	_, err = f.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading content of bytes field: %w", err)
	}

	return buf, nil
}

func readDict(f io.Reader) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	for {
		leadByte, err := readLeadByte(f)
		if err != nil {
			return nil, fmt.Errorf("error reading dict key lead byte: %w", err)
		}

		if leadByte == leadByteValueStop {
			return result, nil
		} else if leadByte != leadByteValueString {
			return nil, fmt.Errorf("unexpected type for dict key field: %v", leadByte)
		}

		key, err := readString(f)
		if err != nil {
			return nil, fmt.Errorf("error reading key of dict field: %w", err)
		}

		value, err := readObject(f)
		if err != nil {
			return nil, fmt.Errorf("error reading value of dict field: %w", err)
		}
		result[key] = value
	}
}

func readString(f io.Reader) (string, error) {
	str, err := readBytes(f)
	return string(str), err
}

func readInt(f io.Reader) (int, error) {
	buf := make([]byte, 1)
	_, err := f.Read(buf)
	if err != nil {
		return -1, fmt.Errorf("error reading length of integer field: %w", err)
	}

	length := buf[0]
	if length == 0 {
		return -1, fmt.Errorf("length of integer field is 0")
	}

	buf = make([]byte, length)
	_, err = f.Read(buf)
	if err != nil {
		return -1, fmt.Errorf("error reading content of integer field: %w", err)
	}

	res := 0
	for i := 0; i < int(length); i++ {
		res = res<<8 + int(buf[i])
	}
	return res, nil
}

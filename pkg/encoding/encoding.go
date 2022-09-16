package encoding

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sort"
)

func writeLeadByte(leadByte byte, f io.Writer) error {
	_, err := f.Write([]byte{leadByte})
	return err
}

func writeDict(dict map[string]interface{}, f io.Writer) error {
	// Sort the dictionnary to have predictable outputs
	keys := make([]string, 0)
	for k, _ := range dict {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		err := writeLeadByte(leadByteValueString, f)
		if err != nil {
			return fmt.Errorf("error writing dict lead byte: %w", err)
		}

		err = writeString(k, f)
		if err != nil {
			return fmt.Errorf("error writing dict key: %w", err)
		}

		err = writeObject(dict[k], f)
		if err != nil {
			return fmt.Errorf("error writing dict value: %w", err)
		}
	}

	return writeLeadByte(leadByteValueStop, f)
}

func writeObject(obj interface{}, f io.Writer) error {
	if dict, ok := obj.(map[string]interface{}); ok {
		err := writeLeadByte(leadByteValueDict, f)
		if err != nil {
			return err
		}
		return writeDict(dict, f)

	} else if str, ok := obj.(string); ok {
		err := writeLeadByte(leadByteValueString, f)
		if err != nil {
			return err
		}
		return writeString(str, f)

	} else if integer, ok := obj.(int); ok {
		err := writeLeadByte(leadByteValueInt, f)
		if err != nil {
			return err
		}
		return writeInt(integer, f)

	} else if bytes, ok := obj.([]byte); ok {
		err := writeLeadByte(leadByteValueBytes, f)
		if err != nil {
			return err
		}
		return writeBytes(bytes, f)
	}
	return fmt.Errorf("unsupported object type '%v': %v", reflect.TypeOf(obj), obj)
}

func writeBytes(bytes []byte, f io.Writer) error {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(bytes)))

	_, err := f.Write(length)
	if err != nil {
		return fmt.Errorf("error writing length of bytes field: %w", err)
	}

	_, err = f.Write(bytes)
	if err != nil {
		return fmt.Errorf("error writing content of bytes field: %w", err)
	}

	return nil
}

func writeString(str string, f io.Writer) error {
	return writeBytes([]byte(str), f)
}

func writeInt(num int, f io.Writer) error {
	if num < 256 {
		_, err := f.Write([]byte{1, byte(num)})
		return err
	} else if num < 65536 {
		_, err := f.Write([]byte{2, byte(num >> 8), byte(num)})
		return err
	} else if num < 16777216 {
		_, err := f.Write([]byte{3, byte(num >> 16), byte(num >> 8), byte(num)})
		return err
	} else {
		_, err := f.Write([]byte{4, byte(num >> 24), byte(num >> 16), byte(num >> 8), byte(num)})
		return err
	}
}

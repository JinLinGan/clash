package config

import (
	"encoding/json"
)

func ToMap(v any) (map[string]any, error) {
	inputContent, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = json.Unmarshal(inputContent, &result)
	return result, err
}

func MergeObjects(objects ...any) (map[string]any, error) {
	result := map[string]any{}
	for _, obj := range objects {
		m, err := ToMap(obj)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			result[k] = v
		}
	}
	return result, nil
}

func MarshalObjects(objects ...any) ([]byte, error) {
	left, right := 0, len(objects)-1
	for left <= right {
		if objects[left] == nil {
			objects[left], objects[right] = objects[right], objects[left]
			right--
			continue
		}
		left++
	}
	if len(objects) <= 1 {
		return json.Marshal(objects[0])
	}
	content, err := MergeObjects(objects...)
	if err != nil {
		return nil, err
	}
	return json.Marshal(content)
}

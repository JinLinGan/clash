package config

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"gopkg.in/yaml.v3"
)

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		r = append(r, strings.Trim(e, " "))
	}
	return
}

// Check if ProxyGroups form DAG(Directed Acyclic Graph), and sort all ProxyGroups by dependency order.
// Meanwhile, record the original index in the config file.
// If loop is detected, return an error with location of loop.
func ProxyGroupsDagSort(groupsConfig []outboundgroup.GroupCommonOption) error {
	type graphNode struct {
		indegree int
		// topological order
		topo int
		// `outdegree` and `from` are used in loop locating
		outdegree int
		option    *outboundgroup.GroupCommonOption
		from      []string
	}

	graph := make(map[string]*graphNode)

	// Step 1.1 build dependency graph
	for _, option := range groupsConfig {
		groupName := option.Name
		if node, ok := graph[groupName]; ok {
			opt := option
			node.option = &opt
		} else {
			opt := option
			graph[groupName] = &graphNode{0, -1, 0, &opt, nil}
		}

		for _, proxy := range option.Proxies {
			if node, ex := graph[proxy]; ex {
				node.indegree++
			} else {
				graph[proxy] = &graphNode{1, -1, 0, nil, nil}
			}
		}
	}
	// Step 1.2 Topological Sort
	// topological index of **ProxyGroup**
	index := 0
	queue := make([]string, 0)
	for name, node := range graph {
		// in the beginning, put nodes that have `node.indegree == 0` into queue.
		if node.indegree == 0 {
			queue = append(queue, name)
		}
	}
	// every element in queue have indegree == 0
	for ; len(queue) > 0; queue = queue[1:] {
		name := queue[0]
		node := graph[name]
		if node.option != nil {
			index++
			groupsConfig[len(groupsConfig)-index] = *node.option
			if len(node.option.Proxies) == 0 {
				delete(graph, name)
				continue
			}

			for _, proxy := range node.option.Proxies {
				child := graph[proxy]
				child.indegree--
				if child.indegree == 0 {
					queue = append(queue, proxy)
				}
			}
		}
		delete(graph, name)
	}

	// no loop is detected, return sorted ProxyGroup
	if len(graph) == 0 {
		return nil
	}

	// if loop is detected, locate the loop and throw an error
	// Step 2.1 rebuild the graph, fill `outdegree` and `from` filed
	for name, node := range graph {
		if node.option == nil {
			continue
		}

		if len(node.option.Proxies) == 0 {
			continue
		}

		for _, proxy := range node.option.Proxies {
			node.outdegree++
			child := graph[proxy]
			if child.from == nil {
				child.from = make([]string, 0, child.indegree)
			}
			child.from = append(child.from, name)
		}
	}
	// Step 2.2 remove nodes outside the loop. so that we have only the loops remain in `graph`
	queue = make([]string, 0)
	// initialize queue with node have outdegree == 0
	for name, node := range graph {
		if node.outdegree == 0 {
			queue = append(queue, name)
		}
	}
	// every element in queue have outdegree == 0
	for ; len(queue) > 0; queue = queue[1:] {
		name := queue[0]
		node := graph[name]
		for _, f := range node.from {
			graph[f].outdegree--
			if graph[f].outdegree == 0 {
				queue = append(queue, f)
			}
		}
		delete(graph, name)
	}
	// Step 2.3 report the elements in loop
	loopElements := make([]string, 0, len(graph))
	for name := range graph {
		loopElements = append(loopElements, name)
		delete(graph, name)
	}
	return fmt.Errorf("loop is detected in ProxyGroup, please check following ProxyGroups: %v", loopElements)
}

// UnmarshalYAML 由于底层只支持 json 转换，先将配置文件转换为json，再调用json.Unmarshal 注:配置(node)必须是一个map[string]any(结构体)
func UnmarshalYAML(node *yaml.Node, v any) error {
	b, err := YamlNodeToJSON(node)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// YamlNodeToJSON converts yaml.Node to json
func YamlNodeToJSON(node *yaml.Node) ([]byte, error) {
	var m map[string]any
	err := node.Decode(&m)
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

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

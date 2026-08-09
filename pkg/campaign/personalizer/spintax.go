// Package personalizer provides deterministic, rule-based campaign
// personalization without external services or model dependencies.
package personalizer

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// Spintax expands nested {option one|option two} expressions. Go template
// actions such as {{.FirstName}} are copied verbatim so they can be evaluated
// after spintax expansion.
type Spintax struct {
	random *rand.Rand
	mu     sync.Mutex
}

// NewSpintax creates a concurrency-safe spintax evaluator.
func NewSpintax() *Spintax {
	var seedBytes [8]byte
	seed := time.Now().UnixNano()
	if _, err := cryptorand.Read(seedBytes[:]); err == nil {
		seed = int64(binary.LittleEndian.Uint64(seedBytes[:]))
	}
	return NewSpintaxWithSource(rand.NewSource(seed))
}

// NewSpintaxWithSource creates an evaluator backed by source. It is useful for
// repeatable tests and callers that need control over variation selection.
func NewSpintaxWithSource(source rand.Source) *Spintax {
	if source == nil {
		source = rand.NewSource(time.Now().UnixNano())
	}
	return &Spintax{random: rand.New(source)}
}

// Evaluate expands all valid spintax groups in input. Unmatched braces and
// ordinary braces without alternatives are preserved, which keeps HTML, CSS,
// JSON, and Go template actions safe to process.
func (s *Spintax) Evaluate(input string) string {
	if s == nil || !strings.Contains(input, "{") {
		return input
	}
	var output strings.Builder
	output.Grow(len(input))
	s.expand(&output, input)
	return output.String()
}

// Intn returns a randomized value in [0, n). It shares the evaluator's lock so
// scenario selection and spintax expansion remain safe under concurrent sends.
func (s *Spintax) Intn(n int) int {
	if n <= 1 {
		return 0
	}
	s.mu.Lock()
	value := s.random.Intn(n)
	s.mu.Unlock()
	return value
}

func (s *Spintax) expand(output *strings.Builder, input string) {
	for i := 0; i < len(input); {
		if input[i] == '\\' && i+1 < len(input) && isSpintaxControl(input[i+1]) {
			output.WriteByte(input[i+1])
			i += 2
			continue
		}
		if input[i] == '{' && i+1 < len(input) && input[i+1] == '{' {
			if closeAt := strings.Index(input[i+2:], "}}"); closeAt >= 0 {
				end := i + 2 + closeAt + 2
				output.WriteString(input[i:end])
				i = end
				continue
			}
		}
		if input[i] != '{' {
			output.WriteByte(input[i])
			i++
			continue
		}

		end, alternatives := findGroup(input, i)
		if end == -1 {
			output.WriteByte(input[i])
			i++
			continue
		}

		if len(alternatives) < 2 {
			output.WriteByte('{')
			s.expand(output, input[i+1:end])
			output.WriteByte('}')
			i = end + 1
			continue
		}

		selected := alternatives[s.Intn(len(alternatives))]
		s.expand(output, input[selected[0]:selected[1]])
		i = end + 1
	}
}

// findGroup returns the closing brace and byte ranges for top-level
// alternatives in the group beginning at start.
func findGroup(input string, start int) (int, [][2]int) {
	depth := 0
	partStart := start + 1
	parts := make([][2]int, 0, 4)
	for i := start + 1; i < len(input); i++ {
		if input[i] == '\\' && i+1 < len(input) {
			i++
			continue
		}
		if input[i] == '{' && i+1 < len(input) && input[i+1] == '{' {
			if closeAt := strings.Index(input[i+2:], "}}"); closeAt >= 0 {
				i += closeAt + 3
				continue
			}
		}
		switch input[i] {
		case '{':
			depth++
		case '}':
			if depth == 0 {
				if len(parts) == 0 {
					return i, nil
				}
				parts = append(parts, [2]int{partStart, i})
				return i, parts
			}
			depth--
		case '|':
			if depth == 0 {
				parts = append(parts, [2]int{partStart, i})
				partStart = i + 1
			}
		}
	}
	return -1, nil
}

func isSpintaxControl(value byte) bool {
	return value == '{' || value == '}' || value == '|' || value == '\\'
}

var defaultSpintax = NewSpintax()

// EvaluateSpintax expands input using the package-level concurrency-safe
// evaluator.
func EvaluateSpintax(input string) string {
	return defaultSpintax.Evaluate(input)
}

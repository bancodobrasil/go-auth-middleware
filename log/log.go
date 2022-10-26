package log

// Level is the log level
// You can use the following levels in your implementation:
// 0: Debug
// 1: Info
// 2: Warn
// 3: Error
// 4: Fatal
// 5: Panic
type Level int

// Logger is the interface that wraps the Log and Logf methods.
type Logger interface {
	// Log logs a message at the given level. Arguments are handled in the manner of fmt.Print.
	Log(level Level, args ...interface{})
	// Logf logs a message at the given level. Arguments are handled in the manner of fmt.Printf.
	Logf(level Level, format string, args ...interface{})
}

var logger Logger

func SetLogger(l Logger) {
	logger = l
}

func Log(level Level, args ...interface{}) {
	if logger != nil {
		logger.Log(level, args...)
	}
}

func Logf(level Level, format string, args ...interface{}) {
	if logger != nil {
		logger.Logf(level, format, args...)
	}
}

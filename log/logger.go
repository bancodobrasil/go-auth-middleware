package log

import (
	"fmt"
	"os"
)

// Logger is a simple logger that prints to stdout
type DefaultLogger struct {
	LogLevel LogLevel
}

func NewDefaultLogger(logLevel LogLevel) *DefaultLogger {
	if logLevel < Debug {
		logLevel = Debug
	} else if logLevel > Panic {
		logLevel = Panic
	}
	return &DefaultLogger{logLevel}
}

// Log prints a line to stdout
func (l *DefaultLogger) Log(level LogLevel, args ...any) {
	if level < l.LogLevel {
		return
	}
	switch level {
	case Debug:
		fmt.Println("DEBUG:", fmt.Sprint(args...))
	case Info:
		fmt.Println("INFO:", fmt.Sprint(args...))
	case Warn:
		fmt.Println("WARN:", fmt.Sprint(args...))
	case Error:
		fmt.Println("ERROR:", fmt.Sprint(args...))
	case Fatal:
		fmt.Println("FATAL:", fmt.Sprint(args...))
		os.Exit(1)
	case Panic:
		panic(fmt.Sprint(args...))
	default:
		fmt.Println(args...)
	}
}

// Logf prints a formatted line to stdout
func (l *DefaultLogger) Logf(level LogLevel, format string, args ...any) {
	if level < l.LogLevel {
		return
	}
	switch level {
	case Debug:
		fmt.Printf("DEBUG: "+format, args...)
	case Info:
		fmt.Printf("INFO: "+format, args...)
	case Warn:
		fmt.Printf("WARN: "+format, args...)
	case Error:
		fmt.Printf("ERROR: "+format, args...)
	case Fatal:
		fmt.Printf("FATAL: "+format, args...)
		os.Exit(1)
	case Panic:
		panic(fmt.Sprintf(format, args...))
	default:
		fmt.Printf(format, args...)
	}
	fmt.Println()
}

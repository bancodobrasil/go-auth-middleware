package main

import (
	"fmt"
	"os"

	"github.com/bancodobrasil/goauth/log"
)

type Logger struct {
}

func (l *Logger) Log(level log.Level, args ...interface{}) {
	switch level {
	case 0:
		fmt.Println("DEBUG: ", args)
	case 1:
		fmt.Println("INFO: ", args)
	case 2:
		fmt.Println("WARN: ", args)
	case 3:
		fmt.Println("ERROR: ", args)
	case 4:
		fmt.Println("FATAL: ", args)
		os.Exit(1)
	case 5:
		panic(fmt.Sprint(args...))
	default:
		fmt.Println(args...)
	}
}

func (l *Logger) Logf(level log.Level, format string, args ...interface{}) {
	switch level {
	case 0:
		fmt.Printf("DEBUG: "+format, args)
	case 1:
		fmt.Printf("INFO: "+format, args)
	case 2:
		fmt.Printf("WARN: "+format, args)
	case 3:
		fmt.Printf("ERROR: "+format, args)
	case 4:
		fmt.Printf("FATAL: "+format, args...)
		os.Exit(1)
	case 5:
		panic(fmt.Sprintf(format, args...))
	default:
		fmt.Printf(format, args...)
	}
	fmt.Println()
}

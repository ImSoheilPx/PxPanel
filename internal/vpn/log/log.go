// Package log is the VPN layer's logging facade.
//
// vpn-ui shipped a standalone op/go-logging wrapper (console+syslog backend,
// file backend, in-memory ring buffer for the web UI). The pxpanel target's
// internal/logger already provides that exact surface — console/syslog backend,
// rotating file backend, buffered log storage with GetLogs — so this package
// adapts rather than duplicates: every call writes through internal/logger.
// That keeps one log file, one buffer and one web-UI log viewer instead of two.
//
// Named internal/vpn/log (not logger) so the two packages can never be confused
// by the import shadowing that bit vpn-ui's own service tree.
package log

import (
	targetlogger "github.com/ImSoheilPx/pxpanel/internal/logger"
)

// Debug logs a debug message.
func Debug(args ...any) { targetlogger.Debug(args...) }

// Debugf logs a formatted debug message.
func Debugf(format string, args ...any) { targetlogger.Debugf(format, args...) }

// Info logs an info message.
func Info(args ...any) { targetlogger.Info(args...) }

// Infof logs a formatted info message.
func Infof(format string, args ...any) { targetlogger.Infof(format, args...) }

// Notice logs a notice message.
func Notice(args ...any) { targetlogger.Notice(args...) }

// Noticef logs a formatted notice message.
func Noticef(format string, args ...any) { targetlogger.Noticef(format, args...) }

// Warning logs a warning message.
func Warning(args ...any) { targetlogger.Warning(args...) }

// Warningf logs a formatted warning message.
func Warningf(format string, args ...any) { targetlogger.Warningf(format, args...) }

// Error logs an error message.
func Error(args ...any) { targetlogger.Error(args...) }

// Errorf logs a formatted error message.
func Errorf(format string, args ...any) { targetlogger.Errorf(format, args...) }

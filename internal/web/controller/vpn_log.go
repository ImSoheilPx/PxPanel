package controller

import "github.com/ImSoheilPx/pxpanel/internal/logger"

// loggerVpnWarning keeps the vpn controller files on the panel logger without
// repeating the import in a dozen files.
func loggerVpnWarning(args ...any) { logger.Warning(args...) }

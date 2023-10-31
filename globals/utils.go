package globals

import (
	_ "embed"
	"strings"
)

const CLOUDFOX_USER_AGENT = "cloudfox"
const CLOUDFOX_LOG_FILE_DIR_NAME = ".cloudfox"
const CLOUDFOX_BASE_DIRECTORY = "cloudfox-output"
const LOOT_DIRECTORY_NAME = "loot"
var CLOUDFOX_VERSION string = strings.TrimSpace(version)
//go:embed VERSION
var version string

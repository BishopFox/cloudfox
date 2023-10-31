package globals

import (
	_ "embed"
)

const CLOUDFOX_USER_AGENT = "cloudfox"
const CLOUDFOX_LOG_FILE_DIR_NAME = ".cloudfox"
const CLOUDFOX_BASE_DIRECTORY = "cloudfox-output"
const LOOT_DIRECTORY_NAME = "loot"
//go:embed VERSION
var CLOUDFOX_VERSION string

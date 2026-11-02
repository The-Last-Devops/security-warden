package i18n

var en = map[string]string{
	"report.title":      "security-warden: machine checkup",
	"report.sources":    "Checked",
	"report.findings":   "Findings",
	"report.none":       "No problems found.",
	"report.fix":        "Fix",
	"report.score":      "Score",
	"report.summary":    "%d findings: %d critical, %d high, %d medium, %d low",
	"report.not_root":   "Note: running without sudo, so ports of other users' processes are not listed.",
	"report.private":    "Everything ran locally. Nothing was sent anywhere.",
	"source.ok":         "%d items",
	"source.error":      "error: %s",
	"severity.critical": "CRITICAL",
	"severity.high":     "HIGH",
	"severity.medium":   "MEDIUM",
	"severity.low":      "LOW",
	"severity.info":     "INFO",

	"source.posture":           "Security settings",
	"source.listening_ports":   "Listening ports",
	"source.remote_services":   "Remote access services",
	"source.remote_tools":      "Tunnels and remote desktop apps",
	"source.docker_containers": "Docker containers",
	"source.docker_ports":      "Docker published ports",
	"source.tailscale":         "Tailscale",
	"source.ssh_keys":          "SSH keys",
	"source.credential_files":  "Credential files",
	"source.services":          "Servers running on this machine",
	"source.outdated_software": "Out-of-date software",

	"skip.platform":          "not supported on this OS yet",
	"skip.lsof":              "lsof not available",
	"skip.docker":            "Docker is not running",
	"skip.tailscale":         "Tailscale not installed",
	"skip.tailscale_stopped": "Tailscale not connected",
	"skip.no_ssh_dir":        "no ~/.ssh folder",
	"skip.homebrew":          "Homebrew not installed",

	"cli.usage": `security-warden: what doors does your machine leave open, and which secrets are lying around?

Usage:
  security-warden [scan] [--lang en|vi] [--json] [--verbose]
  security-warden rules  [--lang en|vi]
  security-warden version

Language: --lang, else SW_LANG, else your system language.
Exit status: 0 no high or critical findings, 1 at least one, 2 error.`,
	"cli.rules_header": "%d rules",

	"count.critical":  "critical",
	"count.high":      "high",
	"count.medium":    "medium",
	"count.low":       "low",
	"report.passed":   "Passed %d of %d checks",
	"report.more":     "Details for every item: security-warden --verbose",
	"report.progress": "Checking",
}

var vi = map[string]string{
	"report.title":      "security-warden: khám máy",
	"report.sources":    "Đã kiểm",
	"report.findings":   "Vấn đề",
	"report.none":       "Không thấy vấn đề nào.",
	"report.fix":        "Cách sửa",
	"report.score":      "Điểm",
	"report.summary":    "%d vấn đề: %d nghiêm trọng, %d cao, %d vừa, %d thấp",
	"report.not_root":   "Lưu ý: chạy không có sudo nên không liệt kê được port của tiến trình thuộc người dùng khác.",
	"report.private":    "Mọi thứ chạy trên máy này. Không gửi gì ra ngoài.",
	"source.ok":         "%d mục",
	"source.error":      "lỗi: %s",
	"severity.critical": "NGHIÊM TRỌNG",
	"severity.high":     "CAO",
	"severity.medium":   "VỪA",
	"severity.low":      "THẤP",
	"severity.info":     "THÔNG TIN",

	"source.posture":           "Cài đặt bảo mật",
	"source.listening_ports":   "Port đang mở",
	"source.remote_services":   "Dịch vụ truy cập từ xa",
	"source.remote_tools":      "Tunnel và app điều khiển từ xa",
	"source.docker_containers": "Container Docker",
	"source.docker_ports":      "Port Docker publish",
	"source.tailscale":         "Tailscale",
	"source.ssh_keys":          "Khoá SSH",
	"source.credential_files":  "File chứa thông tin đăng nhập",
	"source.services":          "Server chạy trên máy",
	"source.outdated_software": "Phần mềm cũ",

	"skip.platform":          "chưa hỗ trợ hệ điều hành này",
	"skip.lsof":              "không có lsof",
	"skip.docker":            "Docker không chạy",
	"skip.tailscale":         "chưa cài Tailscale",
	"skip.tailscale_stopped": "Tailscale chưa kết nối",
	"skip.no_ssh_dir":        "không có thư mục ~/.ssh",
	"skip.homebrew":          "chưa cài Homebrew",

	"cli.usage": `security-warden: máy bạn đang mở những cửa nào, và secret nào đang nằm lộ ra?

Cách dùng:
  security-warden [scan] [--lang en|vi] [--json] [--verbose]
  security-warden rules  [--lang en|vi]
  security-warden version

Ngôn ngữ: --lang, không có thì SW_LANG, không có nữa thì theo ngôn ngữ hệ thống.
Mã thoát: 0 không có vấn đề cao hay nghiêm trọng, 1 có ít nhất một, 2 lỗi.`,
	"cli.rules_header": "%d rule",

	"count.critical":  "nghiêm trọng",
	"count.high":      "cao",
	"count.medium":    "vừa",
	"count.low":       "thấp",
	"report.passed":   "Đạt %d trên %d kiểm tra",
	"report.more":     "Xem chi tiết từng mục: security-warden --verbose",
	"report.progress": "Đang kiểm",
}

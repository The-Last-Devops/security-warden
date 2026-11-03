package report

// Category groups sources the way the UI (web and app) shows them.
func Category(source string) string {
	switch source {
	case "dev_files", "git_remotes", "git_history":
		return "code_secrets"
	case "project_deps":
		return "code_deps"
	case "ssh_keys", "credential_files", "shell_history", "shell_rc", "cloud_config":
		return "secrets"
	case "listening_ports", "remote_services", "remote_tools", "tailscale", "sharing", "authorized_keys", "services", "network_config":
		return "exposure"
	case "posture", "defender", "privilege", "backup":
		return "settings"
	case "persistence", "processes", "apps":
		return "persistence"
	case "ai_agents":
		return "ai"
	case "docker_ports", "docker_containers", "docker_config", "ssh_config", "git_config", "pkg_config", "browser_extensions", "browser_settings", "editor_settings", "editor_extensions":
		return "devtools"
	case "outdated_software":
		return "software"
	}
	return "other"
}

// Scope splits findings into the machine itself and the code on it, so
// problems in old repositories do not hide how the machine is doing.
func Scope(source string) string {
	switch Category(source) {
	case "code_secrets", "code_deps":
		return "code"
	}
	return "machine"
}

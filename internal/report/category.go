package report

// Category groups sources the way the UI (web and app) shows them.
func Category(source string) string {
	switch source {
	case "ssh_keys", "credential_files", "shell_history", "shell_rc", "dev_files", "cloud_config":
		return "secrets"
	case "docker_ports", "docker_containers", "docker_config":
		return "docker"
	case "listening_ports", "remote_services", "remote_tools", "tailscale", "sharing", "authorized_keys", "services", "network_config":
		return "exposure"
	case "posture", "privilege":
		return "settings"
	case "persistence":
		return "persistence"
	case "ai_agents":
		return "ai"
	case "ssh_config", "git_config", "pkg_config", "browser_extensions", "editor_settings", "editor_extensions":
		return "devtools"
	case "outdated_software":
		return "software"
	}
	return "other"
}

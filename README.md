# security-warden

Phần mềm kiểm tra máy làm việc (macOS trước, Windows sau):

- rà soát cấu hình bảo mật (FileVault/BitLocker, firewall, cập nhật…);
- tìm "cửa mở" ra ngoài: port, Docker, Tailscale, tunnel, remote desktop;
- tìm secret để lộ trên máy (SSH key, `.env`, `~/.aws`, kubeconfig…).

Engine + CLI viết bằng Go, rule khai báo bằng YAML + CEL, rule do cộng đồng đóng góp.

Trạng thái: mới định hướng, chưa có code.

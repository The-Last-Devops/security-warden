package vulndb

// Role says how a project lists a package: in its own manifest (direct,
// maybe as a development dependency) or only through another package.
type Role int

const (
	Unknown Role = iota
	Direct
	DirectDev
	Indirect
)

// Commands returns the command that upgrades pkg to fixed in a project
// with this kind of lock file, and the one that shows what pulls pkg in.
// Every command only changes the project's manifest and lock file.
func Commands(kind, pkg, fixed string, role Role) (upgrade, why string) {
	dev := ""
	if role == DirectDev {
		dev = "-D "
	}
	switch kind {
	case KindNPM:
		why = "npm explain " + pkg
		if role == Indirect {
			return "npm update " + pkg, why
		}
		return "npm install " + dev + pkg + "@" + fixed, why
	case KindPNPM:
		why = "pnpm why " + pkg
		if role == Indirect {
			return "pnpm update " + pkg, why
		}
		return "pnpm add " + dev + pkg + "@" + fixed, why
	case KindYarn:
		why = "yarn why " + pkg
		if role == Indirect {
			return "yarn upgrade " + pkg, why // Yarn 1
		}
		return "yarn add " + dev + pkg + "@" + fixed, why
	case KindYarnBerry:
		why = "yarn why " + pkg
		if role == Indirect {
			return "yarn up -R " + pkg, why
		}
		return "yarn add " + dev + pkg + "@" + fixed, why
	case KindPip:
		return "pip install '" + pkg + ">=" + fixed + "'", "pip show " + pkg
	case KindPoetry:
		return "poetry update " + pkg, "poetry show --tree"
	case KindUV:
		return "uv lock --upgrade-package " + pkg, "uv tree --invert --package " + pkg
	case KindPipenv:
		return "pipenv update " + pkg, "pipenv graph --reverse"
	case KindGo:
		return "go get " + pkg + "@v" + fixed + " && go mod tidy", "go mod why -m " + pkg
	case KindCargo:
		return "cargo update -p " + pkg + " --precise " + fixed, "cargo tree -i " + pkg
	case KindBundler:
		return "bundle update --conservative " + pkg, "gem dependency " + pkg + " --reverse-dependencies"
	}
	return "", ""
}

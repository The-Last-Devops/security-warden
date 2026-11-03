package source

import "testing"

// Every source has a schema, and the schema names only real sources, with
// valid types and platforms and no field twice.
func TestSchemaCoversEverySource(t *testing.T) {
	names := map[string]bool{}
	for _, c := range All() {
		names[c.Name] = true
		if _, ok := Schema[c.Name]; !ok {
			t.Errorf("source %s has no entry in Schema (schema.go)", c.Name)
		}
	}
	types := map[string]bool{}
	for _, ty := range FieldTypes {
		types[ty] = true
	}
	plats := map[string]bool{"macos": true, "linux": true, "windows": true}
	for name, info := range Schema {
		if !names[name] {
			t.Errorf("Schema has %s, which is not a source", name)
		}
		if len(info.Platforms) == 0 || len(info.Fields) == 0 {
			t.Errorf("%s: platforms and fields are required", name)
		}
		for _, p := range info.Platforms {
			if !plats[p] {
				t.Errorf("%s: unknown platform %q", name, p)
			}
		}
		seen := map[string]bool{}
		for _, f := range info.Fields {
			if seen[f.Name] {
				t.Errorf("%s: field %s twice", name, f.Name)
			}
			seen[f.Name] = true
			if !types[f.Type] {
				t.Errorf("%s.%s: type %q", name, f.Name, f.Type)
			}
			if f.Desc == "" {
				t.Errorf("%s.%s: no description", name, f.Name)
			}
		}
	}
}

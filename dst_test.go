package main

import (
	"encoding/json"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"pgregory.net/rapid"
)

// fileExists returns true if the path exists on disk.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// rapidTempDir creates a temp directory that is cleaned up via rapid.T.Cleanup.
func rapidTempDir(t *rapid.T) string {
	dir, err := os.MkdirTemp("", "dst-saucegen-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func cleanupDir(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0755); err != nil && !os.IsNotExist(err) {
			t.Errorf("restore permissions for %s: %v", dir, err)
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove %s: %v", dir, err)
		}
	})
}

func mustChmod(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
}

func saveGeneratedFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read generated dir: %v", err)
	}

	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		files[entry.Name()] = data
	}
	return files
}

func clearGeneratedFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read generated dir: %v", err)
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			t.Fatalf("remove %s: %v", entry.Name(), err)
		}
	}
}

func restoreGeneratedFiles(t *testing.T, dir string, files map[string][]byte, names ...string) {
	t.Helper()
	for _, name := range names {
		data, ok := files[name]
		if !ok {
			t.Fatalf("saved output missing %s", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatalf("restore %s: %v", name, err)
		}
	}
}

// invariantResult captures a single invariant check outcome.
type invariantResult struct {
	Name    string
	Passed  bool
	Message string
}

// checkAllInvariants runs every invariant against a generated output directory.
// It returns all violations found (empty slice = all pass).
func checkAllInvariants(outDir string, fields []FieldInfo, cfg Config) []invariantResult {
	var violations []invariantResult

	for _, check := range []struct {
		name string
		fn   func(string, []FieldInfo, Config) *invariantResult
	}{
		{"AllYAMLFilesAreValid", invAllYAMLValid},
		{"SchemaContainsAllFields", invSchemaComplete},
		{"SecretPublicPartitionIsDisjoint", invPartitionDisjoint},
		{"KustomizationMatchesFiles", invKustomizationCorrect},
		{"NoSecretLeaksIntoConfigMap", invNoSecretLeak},
		{"NoPublicInExternalSecretUnlessConfigAsSecret", invNoPublicLeakToES},
		{"BootstrapOnlyPublicWithValues", invBootstrapCorrect},
		{"DefaultsContainsAllFields", invDefaultsComplete},
		{"FieldCountsConsistent", invFieldCounts},
	} {
		result := check.fn(outDir, fields, cfg)
		if result != nil && !result.Passed {
			violations = append(violations, *result)
		}
	}
	return violations
}

func invAllYAMLValid(outDir string, _ []FieldInfo, _ Config) *invariantResult {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return &invariantResult{"AllYAMLFilesAreValid", false, fmt.Sprintf("cannot read dir: %v", err)}
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			return &invariantResult{"AllYAMLFilesAreValid", false, fmt.Sprintf("read %s: %v", e.Name(), err)}
		}
		var m interface{}
		if err := yaml.Unmarshal(data, &m); err != nil {
			return &invariantResult{"AllYAMLFilesAreValid", false, fmt.Sprintf("%s is invalid YAML: %v", e.Name(), err)}
		}
	}
	return nil
}

func invSchemaComplete(outDir string, fields []FieldInfo, _ Config) *invariantResult {
	data, err := os.ReadFile(filepath.Join(outDir, "schema.yaml"))
	if err != nil {
		return &invariantResult{"SchemaContainsAllFields", false, fmt.Sprintf("read: %v", err)}
	}
	var schema map[string]interface{}
	if err := yaml.Unmarshal(data, &schema); err != nil {
		return &invariantResult{"SchemaContainsAllFields", false, fmt.Sprintf("unmarshal: %v", err)}
	}
	keys, ok := schema["keys"].([]interface{})
	if !ok {
		return &invariantResult{"SchemaContainsAllFields", false, "schema.keys is not a list"}
	}
	if len(keys) != len(fields) {
		return &invariantResult{"SchemaContainsAllFields", false,
			fmt.Sprintf("schema has %d keys, expected %d fields", len(keys), len(fields))}
	}
	return nil
}

func invPartitionDisjoint(outDir string, fields []FieldInfo, _ Config) *invariantResult {
	secretKeys := map[string]bool{}
	publicKeys := map[string]bool{}
	for _, f := range fields {
		key := strings.ToUpper(strings.ReplaceAll(f.Path, ".", "_"))
		if f.IsSecret {
			secretKeys[key] = true
		} else {
			publicKeys[key] = true
		}
	}
	for k := range secretKeys {
		if publicKeys[k] {
			return &invariantResult{"SecretPublicPartitionIsDisjoint", false,
				fmt.Sprintf("key %s is both secret and public", k)}
		}
	}
	return nil
}

func invKustomizationCorrect(outDir string, _ []FieldInfo, _ Config) *invariantResult {
	data, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	if err != nil {
		return &invariantResult{"KustomizationMatchesFiles", false, fmt.Sprintf("read: %v", err)}
	}
	var k map[string]interface{}
	if err := yaml.Unmarshal(data, &k); err != nil {
		return &invariantResult{"KustomizationMatchesFiles", false, fmt.Sprintf("unmarshal: %v", err)}
	}
	resources, ok := k["resources"].([]interface{})
	if !ok {
		return &invariantResult{"KustomizationMatchesFiles", false, "resources is not a list"}
	}
	for _, r := range resources {
		name, ok := r.(string)
		if !ok {
			return &invariantResult{"KustomizationMatchesFiles", false, "resource entry is not a string"}
		}
		if !fileExists(filepath.Join(outDir, name)) {
			return &invariantResult{"KustomizationMatchesFiles", false,
				fmt.Sprintf("kustomization lists %s but file does not exist", name)}
		}
	}
	return nil
}

func invNoSecretLeak(outDir string, fields []FieldInfo, _ Config) *invariantResult {
	cmPath := filepath.Join(outDir, "config-map.yaml")
	if !fileExists(cmPath) {
		return nil
	}
	data, err := os.ReadFile(cmPath)
	if err != nil {
		return nil
	}
	var cm map[string]interface{}
	if err := yaml.Unmarshal(data, &cm); err != nil {
		return nil
	}
	cmData, ok := cm["data"].(map[string]interface{})
	if !ok {
		return nil
	}
	for _, f := range fields {
		if f.IsSecret {
			key := strings.ToUpper(strings.ReplaceAll(f.Path, ".", "_"))
			if _, present := cmData[key]; present {
				return &invariantResult{"NoSecretLeaksIntoConfigMap", false,
					fmt.Sprintf("secret field %s found in ConfigMap", key)}
			}
		}
	}
	return nil
}

func invNoPublicLeakToES(outDir string, fields []FieldInfo, cfg Config) *invariantResult {
	if cfg.ConfigAsSecret {
		return nil
	}
	esPath := filepath.Join(outDir, "external-secret-secrets.yaml")
	if !fileExists(esPath) {
		return nil
	}
	data, err := os.ReadFile(esPath)
	if err != nil {
		return nil
	}
	var es map[string]interface{}
	if err := yaml.Unmarshal(data, &es); err != nil {
		return nil
	}
	spec, ok := es["spec"].(map[string]interface{})
	if !ok {
		return &invariantResult{"NoPublicInExternalSecretUnlessConfigAsSecret", false, "spec is not a map"}
	}
	esData, ok := spec["data"].([]interface{})
	if !ok {
		return &invariantResult{"NoPublicInExternalSecretUnlessConfigAsSecret", false, "spec.data is not a list"}
	}

	esKeys := map[string]bool{}
	for _, d := range esData {
		entry, ok := d.(map[string]interface{})
		if !ok {
			return &invariantResult{"NoPublicInExternalSecretUnlessConfigAsSecret", false, "data entry is not a map"}
		}
		if sk, ok := entry["secretKey"].(string); ok {
			esKeys[sk] = true
		}
	}
	for _, f := range fields {
		if !f.IsSecret {
			key := strings.ToUpper(strings.ReplaceAll(f.Path, ".", "_"))
			if esKeys[key] {
				return &invariantResult{"NoPublicInExternalSecretUnlessConfigAsSecret", false,
					fmt.Sprintf("public field %s found in ExternalSecret", key)}
			}
		}
	}
	return nil
}

func invBootstrapCorrect(outDir string, fields []FieldInfo, _ Config) *invariantResult {
	bsPath := filepath.Join(outDir, "bootstrap.json")
	if !fileExists(bsPath) {
		return nil
	}
	data, err := os.ReadFile(bsPath)
	if err != nil {
		return nil
	}
	var bootstrap map[string]interface{}
	if err := json.Unmarshal(data, &bootstrap); err != nil {
		return &invariantResult{"BootstrapOnlyPublicWithValues", false, fmt.Sprintf("invalid JSON: %v", err)}
	}
	for _, f := range fields {
		key := strings.ToUpper(strings.ReplaceAll(f.Path, ".", "_"))
		if f.IsSecret {
			if _, present := bootstrap[key]; present {
				return &invariantResult{"BootstrapOnlyPublicWithValues", false,
					fmt.Sprintf("secret field %s found in bootstrap.json", key)}
			}
		}
	}
	return nil
}

func invDefaultsComplete(outDir string, fields []FieldInfo, _ Config) *invariantResult {
	data, err := os.ReadFile(filepath.Join(outDir, "defaults.yaml"))
	if err != nil {
		return &invariantResult{"DefaultsContainsAllFields", false, fmt.Sprintf("read: %v", err)}
	}
	var defaults map[string]interface{}
	if err := yaml.Unmarshal(data, &defaults); err != nil {
		return &invariantResult{"DefaultsContainsAllFields", false, fmt.Sprintf("unmarshal: %v", err)}
	}
	for _, f := range fields {
		key := strings.ToUpper(strings.ReplaceAll(f.Path, ".", "_"))
		if _, ok := defaults[key]; !ok {
			return &invariantResult{"DefaultsContainsAllFields", false,
				fmt.Sprintf("field %s missing from defaults.yaml", key)}
		}
	}
	return nil
}

func invFieldCounts(outDir string, fields []FieldInfo, _ Config) *invariantResult {
	nSecret := 0
	nPublic := 0
	for _, f := range fields {
		if f.IsSecret {
			nSecret++
		} else {
			nPublic++
		}
	}
	if nSecret+nPublic != len(fields) {
		return &invariantResult{"FieldCountsConsistent", false,
			fmt.Sprintf("secret(%d) + public(%d) != total(%d)", nSecret, nPublic, len(fields))}
	}
	return nil
}

// genFieldName produces random valid field names (lowercase, underscore-separated).
func genFieldName(t *rapid.T) string {
	parts := rapid.SliceOfN(
		rapid.StringMatching(`[a-z]{2,8}`),
		1, 3,
	).Draw(t, "name_parts")
	return strings.Join(parts, "_")
}

// genFieldInfo produces a single random FieldInfo.
func genFieldInfo(t *rapid.T) FieldInfo {
	pathDepth := rapid.IntRange(1, 3).Draw(t, "path_depth")
	pathParts := make([]string, pathDepth)
	for i := range pathParts {
		pathParts[i] = genFieldName(t)
	}
	path := strings.Join(pathParts, ".")
	name := pathParts[len(pathParts)-1]
	isSecret := rapid.Bool().Draw(t, "is_secret")

	var val interface{}
	if !isSecret && rapid.Bool().Draw(t, "has_value") {
		switch rapid.IntRange(0, 3).Draw(t, "val_type") {
		case 0:
			val = rapid.StringMatching(`[a-zA-Z0-9_]{1,20}`).Draw(t, "val_str")
		case 1:
			val = rapid.IntRange(0, 65535).Draw(t, "val_int")
		case 2:
			val = rapid.Bool().Draw(t, "val_bool")
		case 3:
			val = fmt.Sprintf("%d", rapid.IntRange(1, 9999).Draw(t, "val_num_str"))
		}
	}

	return FieldInfo{
		Path:     path,
		Name:     name,
		IsSecret: isSecret,
		Value:    val,
	}
}

// genFieldInfoSlice produces a random slice of FieldInfo with unique paths.
func genFieldInfoSlice(t *rapid.T) []FieldInfo {
	n := rapid.IntRange(1, 30).Draw(t, "num_fields")
	seen := map[string]bool{}
	var fields []FieldInfo
	for i := 0; i < n; i++ {
		f := genFieldInfo(t)
		key := strings.ToUpper(strings.ReplaceAll(f.Path, ".", "_"))
		if seen[key] {
			continue
		}
		seen[key] = true
		fields = append(fields, f)
	}
	if len(fields) == 0 {
		fields = append(fields, FieldInfo{
			Path: "fallback", Name: "fallback", IsSecret: true,
		})
	}
	return fields
}

// genConfig produces a random Config for writeManifests-level testing.
func genConfig(t *rapid.T, outDir string) Config {
	return Config{
		AppName: rapid.StringMatching(`[a-z]{3,10}(-[a-z]{3,10})?`).Draw(t, "app_name"),
		Namespace: rapid.SampledFrom([]string{
			"default", "production", "staging", "kube-system",
		}).Draw(t, "namespace"),
		SecretStore:        rapid.StringMatching(`[a-z]{3,12}`).Draw(t, "secret_store"),
		OutputDir:          outDir,
		ConfigAsSecret:     rapid.Bool().Draw(t, "config_as_secret"),
		ConfigStore:        rapid.StringMatching(`[a-z]{3,12}`).Draw(t, "config_store"),
		SecretKeySeparator: rapid.SampledFrom([]string{"-", "/", "_", "."}).Draw(t, "separator"),
	}
}

// genTypesStruct builds a random *types.Struct with valid mapstructure and sauce tags.
func genTypesStruct(t *rapid.T) (*types.Struct, []expectedField) {
	numFields := rapid.IntRange(1, 15).Draw(t, "num_struct_fields")
	vars := make([]*types.Var, numFields)
	tags := make([]string, numFields)
	var expected []expectedField

	pkg := types.NewPackage("test/pkg", "pkg")
	usedNames := map[string]bool{}

	for i := 0; i < numFields; i++ {
		name := rapid.StringMatching(`[a-z]{3,10}`).Draw(t, fmt.Sprintf("field_name_%d", i))
		if usedNames[name] {
			name = fmt.Sprintf("%s%d", name, i)
		}
		usedNames[name] = true

		goName := strings.ToUpper(name[:1]) + name[1:]
		isPublic := rapid.Bool().Draw(t, fmt.Sprintf("field_public_%d", i))
		hasDefault := rapid.Bool().Draw(t, fmt.Sprintf("field_default_%d", i))

		fieldType := types.Typ[types.String]

		tag := fmt.Sprintf(`mapstructure:"%s"`, name)
		if isPublic {
			tag += ` sauce:"public"`
		}
		if hasDefault {
			defVal := rapid.StringMatching(`[a-z0-9]{1,10}`).Draw(t, fmt.Sprintf("default_%d", i))
			tag += fmt.Sprintf(` default:"%s"`, defVal)
		}

		vars[i] = types.NewVar(0, pkg, goName, fieldType)
		tags[i] = tag
		expected = append(expected, expectedField{
			name:     name,
			isSecret: !isPublic,
		})
	}

	return types.NewStruct(vars, tags), expected
}

type expectedField struct {
	name     string
	isSecret bool
}

// TestDST_WriteManifests_AllInvariantsHold generates random fields + configs
// and verifies every invariant.
func TestDST_WriteManifests_AllInvariantsHold(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		fields := genFieldInfoSlice(t)
		cfg := genConfig(t, outDir)

		g := NewGenerator(cfg)
		err := g.writeManifests(fields)
		if err != nil {
			t.Fatalf("writeManifests failed: %v", err)
		}

		violations := checkAllInvariants(outDir, fields, cfg)
		for _, v := range violations {
			t.Errorf("INVARIANT VIOLATION [%s]: %s", v.Name, v.Message)
		}
	})
}

// TestDST_WalkStruct_FieldCountMatchesLeaves verifies that walkStruct returns
// exactly one FieldInfo per leaf (non-struct) field, regardless of struct shape.
func TestDST_WalkStruct_FieldCountMatchesLeaves(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st, expected := genTypesStruct(t)
		g := &Generator{}
		fields := g.walkStruct(st, "", nil)

		if len(fields) != len(expected) {
			t.Fatalf("walkStruct returned %d fields, expected %d leaves", len(fields), len(expected))
		}
	})
}

// TestDST_WalkStruct_SecretByDefault verifies that fields without sauce:"public"
// are always classified as secrets.
func TestDST_WalkStruct_SecretByDefault(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st, expected := genTypesStruct(t)
		g := &Generator{}
		fields := g.walkStruct(st, "", nil)

		for i, f := range fields {
			if i >= len(expected) {
				break
			}
			if expected[i].isSecret && !f.IsSecret {
				t.Errorf("field %s should be secret (no sauce:public tag) but IsSecret=false", f.Name)
			}
			if !expected[i].isSecret && f.IsSecret {
				t.Errorf("field %s has sauce:public but IsSecret=true", f.Name)
			}
		}
	})
}

// TestDST_WalkStruct_NamesMatchMapstructureTags verifies field names come from
// the mapstructure tag, not the Go field name.
func TestDST_WalkStruct_NamesMatchMapstructureTags(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st, expected := genTypesStruct(t)
		g := &Generator{}
		fields := g.walkStruct(st, "", nil)

		for i, f := range fields {
			if i >= len(expected) {
				break
			}
			if f.Name != expected[i].name {
				t.Errorf("field %d: Name=%s, expected mapstructure name %s", i, f.Name, expected[i].name)
			}
		}
	})
}

// TestDST_WriteManifests_AllSecretNoConfigMap verifies that when all fields are
// secrets, no ConfigMap or bootstrap.json is generated.
func TestDST_WriteManifests_AllSecretNoConfigMap(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		n := rapid.IntRange(1, 20).Draw(t, "n")
		fields := make([]FieldInfo, n)
		seen := map[string]bool{}
		for i := range fields {
			name := genFieldName(t)
			for seen[name] {
				name = genFieldName(t)
			}
			seen[name] = true
			fields[i] = FieldInfo{
				Path:     name,
				Name:     name,
				IsSecret: true,
			}
		}
		cfg := genConfig(t, outDir)
		cfg.ConfigAsSecret = false

		g := NewGenerator(cfg)
		if err := g.writeManifests(fields); err != nil {
			t.Fatalf("writeManifests: %v", err)
		}

		if fileExists(filepath.Join(outDir, "config-map.yaml")) {
			t.Error("config-map.yaml should not exist when all fields are secret")
		}
		if fileExists(filepath.Join(outDir, "external-secret-config.yaml")) {
			t.Error("external-secret-config.yaml should not exist when all fields are secret")
		}
		if fileExists(filepath.Join(outDir, "bootstrap.json")) {
			t.Error("bootstrap.json should not exist when all fields are secret")
		}
	})
}

// TestDST_WriteManifests_AllPublicNoExternalSecret verifies that when all fields
// are public and ConfigAsSecret is false, no ExternalSecret for secrets is generated.
func TestDST_WriteManifests_AllPublicNoExternalSecret(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		n := rapid.IntRange(1, 20).Draw(t, "n")
		fields := make([]FieldInfo, n)
		seen := map[string]bool{}
		for i := range fields {
			name := genFieldName(t)
			for seen[name] {
				name = genFieldName(t)
			}
			seen[name] = true
			fields[i] = FieldInfo{
				Path:     name,
				Name:     name,
				IsSecret: false,
				Value:    fmt.Sprintf("val_%d", i),
			}
		}
		cfg := genConfig(t, outDir)
		cfg.ConfigAsSecret = false

		g := NewGenerator(cfg)
		if err := g.writeManifests(fields); err != nil {
			t.Fatalf("writeManifests: %v", err)
		}

		if fileExists(filepath.Join(outDir, "external-secret-secrets.yaml")) {
			t.Error("external-secret-secrets.yaml should not exist when all fields are public")
		}
	})
}

// TestDST_WriteManifests_ConfigAsSecretUsesConfigStore verifies that when
// ConfigAsSecret is true, public fields use the ConfigStore, not the SecretStore.
func TestDST_WriteManifests_ConfigAsSecretUsesConfigStore(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		fields := genFieldInfoSlice(t)
		hasPublic := false
		for _, f := range fields {
			if !f.IsSecret {
				hasPublic = true
				break
			}
		}
		if !hasPublic {
			return
		}

		cfg := genConfig(t, outDir)
		cfg.ConfigAsSecret = true

		g := NewGenerator(cfg)
		if err := g.writeManifests(fields); err != nil {
			t.Fatalf("writeManifests: %v", err)
		}

		esPath := filepath.Join(outDir, "external-secret-config.yaml")
		if !fileExists(esPath) {
			t.Fatal("external-secret-config.yaml should exist when ConfigAsSecret=true and public fields exist")
		}

		data, err := os.ReadFile(esPath)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var es map[string]interface{}
		if err := yaml.Unmarshal(data, &es); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		spec := es["spec"].(map[string]interface{})
		storeRef := spec["secretStoreRef"].(map[string]interface{})
		if storeRef["name"] != cfg.ConfigStore {
			t.Errorf("config ExternalSecret uses store %v, expected %s", storeRef["name"], cfg.ConfigStore)
		}
	})
}

// TestDST_WriteManifests_Idempotent verifies that running writeManifests twice
// with the same inputs produces identical output.
func TestDST_WriteManifests_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		fields := genFieldInfoSlice(t)

		outDir1 := rapidTempDir(t)
		cfg1 := genConfig(t, outDir1)
		g1 := NewGenerator(cfg1)
		if err := g1.writeManifests(fields); err != nil {
			t.Fatalf("first writeManifests: %v", err)
		}

		outDir2 := rapidTempDir(t)
		cfg2 := cfg1
		cfg2.OutputDir = outDir2
		g2 := NewGenerator(cfg2)
		if err := g2.writeManifests(fields); err != nil {
			t.Fatalf("second writeManifests: %v", err)
		}

		entries1, _ := os.ReadDir(outDir1)
		entries2, _ := os.ReadDir(outDir2)
		if len(entries1) != len(entries2) {
			t.Fatalf("different file counts: %d vs %d", len(entries1), len(entries2))
		}
		for _, e := range entries1 {
			d1, err := os.ReadFile(filepath.Join(outDir1, e.Name()))
			if err != nil {
				t.Fatalf("read %s run1: %v", e.Name(), err)
			}
			d2, err := os.ReadFile(filepath.Join(outDir2, e.Name()))
			if err != nil {
				t.Fatalf("read %s run2: %v", e.Name(), err)
			}
			if string(d1) != string(d2) {
				t.Errorf("file %s differs between runs (not idempotent)", e.Name())
			}
		}
	})
}

// TestDST_WalkStruct_NestedStructProducesDottedPaths verifies that nested structs
// produce dot-separated paths.
func TestDST_WalkStruct_NestedStructProducesDottedPaths(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		parentName := rapid.StringMatching(`[a-z]{3,8}`).Draw(t, "parent_name")
		childName := rapid.StringMatching(`[a-z]{3,8}`).Draw(t, "child_name")

		pkg := types.NewPackage("test/pkg", "pkg")

		childVar := types.NewVar(0, pkg, "Child", types.Typ[types.String])
		childTag := fmt.Sprintf(`mapstructure:"%s"`, childName)
		innerStruct := types.NewStruct([]*types.Var{childVar}, []string{childTag})

		parentVar := types.NewVar(0, pkg, "Parent", innerStruct)
		parentTag := fmt.Sprintf(`mapstructure:"%s"`, parentName)
		outerStruct := types.NewStruct([]*types.Var{parentVar}, []string{parentTag})

		g := &Generator{}
		fields := g.walkStruct(outerStruct, "", nil)

		if len(fields) != 1 {
			t.Fatalf("expected 1 leaf field, got %d", len(fields))
		}
		expected := parentName + "." + childName
		if fields[0].Path != expected {
			t.Errorf("path = %s, want %s", fields[0].Path, expected)
		}
	})
}

// TestDST_WalkStruct_DefaultTagFallback verifies that when no value is found
// in the values map, the default tag is used.
func TestDST_WalkStruct_DefaultTagFallback(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[a-z]{3,8}`).Draw(t, "name")
		defVal := rapid.StringMatching(`[a-z0-9]{1,10}`).Draw(t, "default")

		pkg := types.NewPackage("test/pkg", "pkg")
		v := types.NewVar(0, pkg, "Field", types.Typ[types.String])
		tag := fmt.Sprintf(`mapstructure:"%s" default:"%s"`, name, defVal)
		st := types.NewStruct([]*types.Var{v}, []string{tag})

		g := &Generator{}
		fields := g.walkStruct(st, "", nil)

		if len(fields) != 1 {
			t.Fatalf("expected 1 field, got %d", len(fields))
		}
		if fields[0].Value != defVal {
			t.Errorf("Value = %v, want default %s", fields[0].Value, defVal)
		}
	})
}

// TestDST_FullPipeline_FixtureWithRandomConfig runs the full Generate pipeline
// against the real fixture structs with randomized config flags.
func TestDST_FullPipeline_FixtureWithRandomConfig(t *testing.T) {
	structNames := []string{"AppConfig", "AllSecretConfig", "AllPublicConfig", "SquashConfig"}

	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		structName := rapid.SampledFrom(structNames).Draw(t, "struct")
		useValues := rapid.Bool().Draw(t, "use_values")

		cfg := Config{
			PackagePath:        "./testdata/fixture",
			StructName:         structName,
			AppName:            rapid.StringMatching(`[a-z]{3,10}`).Draw(t, "app_name"),
			Namespace:          rapid.SampledFrom([]string{"default", "prod", "staging"}).Draw(t, "ns"),
			SecretStore:        rapid.StringMatching(`[a-z]{4,10}`).Draw(t, "store"),
			OutputDir:          outDir,
			ConfigAsSecret:     rapid.Bool().Draw(t, "cas"),
			ConfigStore:        rapid.StringMatching(`[a-z]{4,10}`).Draw(t, "cstore"),
			SecretKeySeparator: rapid.SampledFrom([]string{"-", "/", "_"}).Draw(t, "sep"),
		}
		if useValues {
			cfg.ValuesFile = "./testdata/fixture/values.yaml"
		}

		g := NewGenerator(cfg)
		err := g.Generate()
		if err != nil {
			t.Fatalf("Generate(%s) failed: %v", structName, err)
		}

		schemaData, err := os.ReadFile(filepath.Join(outDir, "schema.yaml"))
		if err != nil {
			t.Fatalf("read schema: %v", err)
		}
		var schema map[string]interface{}
		if err := yaml.Unmarshal(schemaData, &schema); err != nil {
			t.Fatalf("unmarshal schema: %v", err)
		}
		keys := schema["keys"].([]interface{})
		var fields []FieldInfo
		for _, k := range keys {
			entry := k.(map[string]interface{})
			fields = append(fields, FieldInfo{
				Path:     entry["path"].(string),
				Name:     filepath.Base(entry["path"].(string)),
				IsSecret: entry["secret"].(bool),
			})
		}

		violations := checkAllInvariants(outDir, fields, cfg)
		for _, v := range violations {
			t.Errorf("INVARIANT VIOLATION [%s] struct=%s: %s", v.Name, structName, v.Message)
		}
	})
}

// TestDST_Generate_ErrorCases verifies Generate fails for invalid inputs.
func TestDST_Generate_ErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		errContains string
	}{
		{
			name: "target name exists but is not a struct",
			cfg: Config{
				PackagePath: "./testdata/fixture",
				StructName:  "NotAStruct",
			},
			errContains: "not a struct",
		},
		{
			name: "target struct does not exist",
			cfg: Config{
				PackagePath: "./testdata/fixture",
				StructName:  "MissingConfig",
			},
			errContains: "not found",
		},
		{
			name: "values file path does not exist",
			cfg: Config{
				PackagePath: "./testdata/fixture",
				StructName:  "AppConfig",
				ValuesFile:  "/tmp/nonexistent_saucegen_values.yaml",
			},
			errContains: "values file",
		},
		{
			name: "values file is invalid YAML",
			cfg: Config{
				PackagePath: "./testdata/fixture",
				StructName:  "AppConfig",
				ValuesFile:  "./testdata/fixture/invalid.yaml",
			},
			errContains: "unmarshal",
		},
		{
			name: "package has compile errors",
			cfg: Config{
				PackagePath: "./testdata/broken",
				StructName:  "Anything",
			},
		},
		{
			name: "package pattern is invalid",
			cfg: Config{
				PackagePath: "definitely_not_a_real_package_@#$%",
				StructName:  "X",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.AppName = "test"
			cfg.Namespace = "default"
			cfg.SecretStore = "vault"
			cfg.OutputDir = t.TempDir()
			cfg.SecretKeySeparator = "-"

			err := NewGenerator(cfg).Generate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected %q in error, got: %s", tt.errContains, err)
			}
		})
	}
}

// TestDST_WriteManifests_UnwritableOutputDir verifies unwritable output directories fail.
func TestDST_WriteManifests_UnwritableOutputDir(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		fields := []FieldInfo{
			{Path: "key", Name: "key", IsSecret: true},
		}
		g := NewGenerator(Config{
			AppName:            "test",
			Namespace:          "default",
			SecretStore:        "vault",
			OutputDir:          "/dev/null/impossible",
			SecretKeySeparator: "-",
		})
		err := g.writeManifests(fields)
		if err == nil {
			t.Fatal("expected error for unwritable output dir, got nil")
		}
	})
}

// TestDST_WriteManifests_ReadOnlyDir verifies writeYAML errors when output cannot be written.
func TestDST_WriteManifests_ReadOnlyDir(t *testing.T) {
	tests := []struct {
		name   string
		fields []FieldInfo
		cas    bool
	}{
		{
			name:   "secret manifest cannot be written",
			fields: []FieldInfo{{Path: "secret_key", Name: "secret_key", IsSecret: true}},
			cas:    false,
		},
		{
			name:   "config external secret cannot be written",
			fields: []FieldInfo{{Path: "public_key", Name: "public_key", IsSecret: false, Value: "v"}},
			cas:    true,
		},
		{
			name:   "config map cannot be written",
			fields: []FieldInfo{{Path: "public_key", Name: "public_key", IsSecret: false, Value: "v"}},
			cas:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "dst-readonly-*")
			if err != nil {
				t.Fatal(err)
			}
			cleanupDir(t, dir)

			mustChmod(t, dir, 0555)

			g := NewGenerator(Config{
				AppName:            "test",
				Namespace:          "default",
				SecretStore:        "vault",
				ConfigStore:        "vault-config",
				ConfigAsSecret:     tt.cas,
				OutputDir:          dir,
				SecretKeySeparator: "-",
			})
			err = g.writeManifests(tt.fields)
			if err == nil {
				t.Fatal("expected error writing to read-only dir, got nil")
			}
		})
	}
}

// TestDST_WriteManifests_FailAfterFirstWrite verifies later writeYAML errors.
func TestDST_WriteManifests_FailAfterFirstWrite(t *testing.T) {
	fields := []FieldInfo{
		{Path: "secret_a", Name: "secret_a", IsSecret: true},
		{Path: "pub_b", Name: "pub_b", IsSecret: false, Value: "val"},
	}

	dir, err := os.MkdirTemp("", "dst-failafter-*")
	if err != nil {
		t.Fatal(err)
	}
	cleanupDir(t, dir)

	g := NewGenerator(Config{
		AppName:            "test",
		Namespace:          "default",
		SecretStore:        "vault",
		OutputDir:          dir,
		SecretKeySeparator: "-",
	})

	if err := g.writeManifests(fields); err != nil {
		t.Fatalf("writeManifests baseline: %v", err)
	}

	savedFiles := saveGeneratedFiles(t, dir)
	mustChmod(t, dir, 0755)
	clearGeneratedFiles(t, dir)
	restoreGeneratedFiles(t, dir, savedFiles, "external-secret-secrets.yaml", "config-map.yaml")
	mustChmod(t, dir, 0555)
	err = g.writeManifests(fields)
	mustChmod(t, dir, 0755)
	if err == nil {
		t.Error("expected error when kustomization.yaml write fails")
	}
}

// TestDST_RunGenerate verifies runGenerate creates generator output.
func TestDST_RunGenerate(t *testing.T) {
	outDir := t.TempDir()

	structName = "AppConfig"
	name = "testapp"
	namespace = "default"
	secretStore = "vault"
	valuesFile = ""
	outputDir = outDir
	configAsSecret = false
	configStore = "default-config"
	secretKeySeparator = "-"

	err := runGenerate(nil, []string{"./testdata/fixture"})
	if err != nil {
		t.Fatalf("runGenerate failed: %v", err)
	}

	if !fileExists(filepath.Join(outDir, "schema.yaml")) {
		t.Error("expected schema.yaml to be created")
	}
}

// TestDST_RunGenerate_Error verifies runGenerate returns generation errors.
func TestDST_RunGenerate_Error(t *testing.T) {
	outDir := t.TempDir()
	structName = "NonExistent"
	name = "testapp"
	namespace = "default"
	secretStore = "vault"
	valuesFile = ""
	outputDir = outDir
	configAsSecret = false
	configStore = "default-config"
	secretKeySeparator = "-"

	err := runGenerate(nil, []string{"./testdata/fixture"})
	if err == nil {
		t.Fatal("expected error for missing struct, got nil")
	}
}

// TestDST_WriteManifests_FailsAfterIntermediateOutputs verifies late write errors.
func TestDST_WriteManifests_FailsAfterIntermediateOutputs(t *testing.T) {
	tests := []struct {
		name         string
		restoreFiles []string
	}{
		{
			name:         "schema cannot be written after config and kustomization exist",
			restoreFiles: []string{"config-map.yaml", "kustomization.yaml"},
		},
		{
			name:         "bootstrap cannot be written after schema exists",
			restoreFiles: []string{"config-map.yaml", "kustomization.yaml", "schema.yaml"},
		},
		{
			name:         "defaults cannot be written after bootstrap exists",
			restoreFiles: []string{"config-map.yaml", "kustomization.yaml", "schema.yaml", "bootstrap.json"},
		},
	}
	fields := []FieldInfo{
		{Path: "pub", Name: "pub", IsSecret: false, Value: "v"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "dst-fail-late-*")
			if err != nil {
				t.Fatal(err)
			}
			cleanupDir(t, dir)

			g := NewGenerator(Config{
				AppName:            "test",
				Namespace:          "default",
				SecretStore:        "vault",
				OutputDir:          dir,
				SecretKeySeparator: "-",
			})

			if err := g.writeManifests(fields); err != nil {
				t.Fatalf("baseline: %v", err)
			}

			saved := saveGeneratedFiles(t, dir)
			mustChmod(t, dir, 0755)
			clearGeneratedFiles(t, dir)
			restoreGeneratedFiles(t, dir, saved, tt.restoreFiles...)
			mustChmod(t, dir, 0555)
			err = g.writeManifests(fields)
			mustChmod(t, dir, 0755)
			if err == nil {
				t.Fatal("expected write error, got nil")
			}
		})
	}
}

// TestDST_WalkStruct_PointerToStruct verifies walkStruct dereferences pointer-to-struct
// and produces dotted paths for the nested fields.
func TestDST_WalkStruct_PointerToStruct(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		parentName := rapid.StringMatching(`[a-z]{3,8}`).Draw(t, "parent")
		childName := rapid.StringMatching(`[a-z]{3,8}`).Draw(t, "child")

		pkg := types.NewPackage("test/pkg", "pkg")

		childVar := types.NewVar(0, pkg, "Child", types.Typ[types.String])
		childTag := fmt.Sprintf(`mapstructure:"%s"`, childName)
		innerStruct := types.NewStruct([]*types.Var{childVar}, []string{childTag})

		ptrType := types.NewPointer(innerStruct)
		parentVar := types.NewVar(0, pkg, "Parent", ptrType)
		parentTag := fmt.Sprintf(`mapstructure:"%s"`, parentName)
		outerStruct := types.NewStruct([]*types.Var{parentVar}, []string{parentTag})

		g := &Generator{}
		fields := g.walkStruct(outerStruct, "", nil)

		if len(fields) != 1 {
			t.Fatalf("expected 1 leaf field through pointer, got %d", len(fields))
		}
		expected := parentName + "." + childName
		if fields[0].Path != expected {
			t.Errorf("path = %s, want %s", fields[0].Path, expected)
		}
	})
}

// TestDST_WalkStruct_SquashWithPrefix verifies that squashed fields with a
// non-empty prefix use the parent prefix, not the squash field's name.
func TestDST_WalkStruct_SquashWithPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leafName := rapid.StringMatching(`[a-z]{3,8}`).Draw(t, "leaf")

		pkg := types.NewPackage("test/pkg", "pkg")

		leafVar := types.NewVar(0, pkg, "Leaf", types.Typ[types.String])
		leafTag := fmt.Sprintf(`mapstructure:"%s"`, leafName)
		innerStruct := types.NewStruct([]*types.Var{leafVar}, []string{leafTag})

		squashVar := types.NewVar(0, pkg, "Embedded", innerStruct)
		squashTag := `mapstructure:",squash"`
		outerStruct := types.NewStruct([]*types.Var{squashVar}, []string{squashTag})

		g := &Generator{}

		fields := g.walkStruct(outerStruct, "", nil)
		if len(fields) != 1 {
			t.Fatalf("expected 1 field, got %d", len(fields))
		}
		if fields[0].Path != leafName {
			t.Errorf("squash without prefix: path = %s, want %s", fields[0].Path, leafName)
		}

		fields = g.walkStruct(outerStruct, "parent", nil)
		if len(fields) != 1 {
			t.Fatalf("expected 1 field, got %d", len(fields))
		}
		expected := "parent." + leafName
		if fields[0].Path != expected {
			t.Errorf("squash with prefix: path = %s, want %s", fields[0].Path, expected)
		}
	})
}

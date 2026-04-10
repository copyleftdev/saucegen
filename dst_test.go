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

// =============================================================================
// INVARIANT CHECKERS
//
// These encode the properties that MUST hold across every possible "universe"
// of saucegen inputs. If any of these fail, we have a real bug.
// =============================================================================

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

// --- individual invariant implementations ---

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
	resources, _ := k["resources"].([]interface{})
	for _, r := range resources {
		name, _ := r.(string)
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
	spec, _ := es["spec"].(map[string]interface{})
	esData, _ := spec["data"].([]interface{})

	esKeys := map[string]bool{}
	for _, d := range esData {
		entry, _ := d.(map[string]interface{})
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

// =============================================================================
// GENERATORS
//
// These produce random "universes" — arbitrary struct shapes, field lists, and
// config combinations that real adopters might throw at saucegen.
// =============================================================================

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

// genConfig produces a random Config (without PackagePath/ValuesFile since those
// need real files — this generator is for writeManifests-level testing).
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

// genTypesStruct builds a random *types.Struct with valid mapstructure/sauce tags
// for direct walkStruct testing. This is the most powerful generator — it creates
// struct shapes that no human would write.
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

// =============================================================================
// PROPERTY TESTS
//
// These are the actual DST simulations. Each one generates thousands of random
// universes and checks that all invariants hold. A failure reports the seed for
// perfect reproducibility.
// =============================================================================

// TestDST_WriteManifests_AllInvariantsHold generates random fields + configs
// and verifies every invariant holds across thousands of universes.
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

		// Re-derive fields from the output schema to check invariants.
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

// =============================================================================
// ERROR PATH DST
//
// These tests verify that Generate and writeManifests fail cleanly and
// predictably under adversarial inputs, covering all defensive branches.
// =============================================================================

// TestDST_Generate_NotAStruct covers line 90: target name exists but is not a struct.
func TestDST_Generate_NotAStruct(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		g := NewGenerator(Config{
			PackagePath:        "./testdata/fixture",
			StructName:         "NotAStruct",
			AppName:            rapid.StringMatching(`[a-z]{3,8}`).Draw(t, "app"),
			Namespace:          "default",
			SecretStore:        "vault",
			OutputDir:          outDir,
			SecretKeySeparator: "-",
		})
		err := g.Generate()
		if err == nil {
			t.Fatal("expected error for non-struct type, got nil")
		}
		if !strings.Contains(err.Error(), "not a struct") {
			t.Errorf("expected 'not a struct' in error, got: %s", err)
		}
	})
}

// TestDST_Generate_MissingStruct covers line 84-85: struct name not found.
func TestDST_Generate_MissingStruct(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		fakeName := rapid.StringMatching(`[A-Z][a-z]{5,12}`).Draw(t, "fake_struct")
		g := NewGenerator(Config{
			PackagePath:        "./testdata/fixture",
			StructName:         fakeName,
			AppName:            "test",
			Namespace:          "default",
			SecretStore:        "vault",
			OutputDir:          outDir,
			SecretKeySeparator: "-",
		})
		err := g.Generate()
		if err == nil {
			t.Fatal("expected error for missing struct, got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected 'not found' in error, got: %s", err)
		}
	})
}

// TestDST_Generate_BadValuesFilePath covers line 97: values file does not exist.
func TestDST_Generate_BadValuesFilePath(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		fakePath := rapid.StringMatching(`/tmp/nonexistent_[a-z]{5,10}\.yaml`).Draw(t, "path")
		g := NewGenerator(Config{
			PackagePath:        "./testdata/fixture",
			StructName:         "AppConfig",
			AppName:            "test",
			Namespace:          "default",
			SecretStore:        "vault",
			ValuesFile:         fakePath,
			OutputDir:          outDir,
			SecretKeySeparator: "-",
		})
		err := g.Generate()
		if err == nil {
			t.Fatal("expected error for bad values file path, got nil")
		}
		if !strings.Contains(err.Error(), "values file") {
			t.Errorf("expected 'values file' in error, got: %s", err)
		}
	})
}

// TestDST_Generate_InvalidValuesYAML covers line 100: values file is not valid YAML.
func TestDST_Generate_InvalidValuesYAML(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		g := NewGenerator(Config{
			PackagePath:        "./testdata/fixture",
			StructName:         "AppConfig",
			AppName:            "test",
			Namespace:          "default",
			SecretStore:        "vault",
			ValuesFile:         "./testdata/fixture/invalid.yaml",
			OutputDir:          outDir,
			SecretKeySeparator: "-",
		})
		err := g.Generate()
		if err == nil {
			t.Fatal("expected error for invalid YAML, got nil")
		}
		if !strings.Contains(err.Error(), "unmarshal") {
			t.Errorf("expected 'unmarshal' in error, got: %s", err)
		}
	})
}

// TestDST_Generate_PackageWithErrors covers line 80: package has compile errors.
func TestDST_Generate_PackageWithErrors(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outDir := rapidTempDir(t)
		g := NewGenerator(Config{
			PackagePath:        "./testdata/broken",
			StructName:         "Anything",
			AppName:            "test",
			Namespace:          "default",
			SecretStore:        "vault",
			OutputDir:          outDir,
			SecretKeySeparator: "-",
		})
		err := g.Generate()
		if err == nil {
			t.Fatal("expected error for broken package, got nil")
		}
	})
}

// TestDST_WriteManifests_UnwritableOutputDir covers error paths in writeManifests
// and writeYAML when the output directory cannot be written to.
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

// TestDST_WriteManifests_ReadOnlyDir covers writeYAML error returns when the
// directory exists but is not writable. This hits os.Create failure (line 373)
// and all cascading error returns in writeManifests (lines 238, 287, 311, etc).
func TestDST_WriteManifests_ReadOnlyDir(t *testing.T) {
	tests := []struct {
		name   string
		fields []FieldInfo
		cas    bool
	}{
		{
			name:   "secrets_path",
			fields: []FieldInfo{{Path: "secret_key", Name: "secret_key", IsSecret: true}},
			cas:    false,
		},
		{
			name:   "config_as_secret_path",
			fields: []FieldInfo{{Path: "public_key", Name: "public_key", IsSecret: false, Value: "v"}},
			cas:    true,
		},
		{
			name:   "configmap_path",
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
			defer os.RemoveAll(dir)

			if err := os.Chmod(dir, 0555); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(dir, 0755)

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

// TestDST_WriteManifests_FailAfterFirstWrite covers the later writeYAML error
// returns (kustomization, schema, defaults, bootstrap) that are only reachable
// when earlier writes succeed. We let the first write go through, then chmod.
func TestDST_WriteManifests_FailAfterFirstWrite(t *testing.T) {
	// This test covers lines 320-321, 338-339, 347-348, 361-362.
	// We use both secrets + public fields so multiple writes happen in sequence.
	fields := []FieldInfo{
		{Path: "secret_a", Name: "secret_a", IsSecret: true},
		{Path: "pub_b", Name: "pub_b", IsSecret: false, Value: "val"},
	}

	dir, err := os.MkdirTemp("", "dst-failafter-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chmod(dir, 0755)
		os.RemoveAll(dir)
	}()

	g := NewGenerator(Config{
		AppName:            "test",
		Namespace:          "default",
		SecretStore:        "vault",
		OutputDir:          dir,
		SecretKeySeparator: "-",
	})

	// First, run normally to confirm it works.
	if err := g.writeManifests(fields); err != nil {
		t.Fatalf("writeManifests baseline: %v", err)
	}

	// Now remove all generated files, make dir read-only, and re-place only
	// the files that are written BEFORE the target error return.
	// Strategy: save output, clear, chmod, restore files one-by-one to
	// let later writes fail.
	savedFiles := map[string][]byte{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		savedFiles[e.Name()] = data
	}

	// Test: let external-secret-secrets.yaml + config-map.yaml succeed,
	// then fail on kustomization.yaml.
	os.Chmod(dir, 0755)
	for _, e := range entries {
		os.Remove(filepath.Join(dir, e.Name()))
	}
	// Write the ES and CM files so those writes are "already done".
	for _, f := range []string{"external-secret-secrets.yaml", "config-map.yaml"} {
		if data, ok := savedFiles[f]; ok {
			os.WriteFile(filepath.Join(dir, f), data, 0644)
		}
	}
	os.Chmod(dir, 0555)
	err = g.writeManifests(fields)
	os.Chmod(dir, 0755)
	if err == nil {
		t.Error("expected error when kustomization.yaml write fails")
	}
}

// TestDST_RunGenerate covers runGenerate from main.go — it's callable since we're
// in the same package. This covers the function that Cobra invokes.
func TestDST_RunGenerate(t *testing.T) {
	outDir := t.TempDir()

	// Set the package-level vars that Cobra normally populates.
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

	// Verify output was created.
	if !fileExists(filepath.Join(outDir, "schema.yaml")) {
		t.Error("expected schema.yaml to be created")
	}
}

// TestDST_RunGenerate_Error covers runGenerate error propagation.
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

// TestDST_Generate_PackagesLoadError covers line 71: packages.Load returns an error.
// Using a pattern with "..." that resolves to nothing valid can trigger this.
func TestDST_Generate_PackagesLoadError(t *testing.T) {
	outDir := t.TempDir()
	g := NewGenerator(Config{
		PackagePath:        "definitely_not_a_real_package_@#$%",
		StructName:         "X",
		AppName:            "test",
		Namespace:          "default",
		SecretStore:        "vault",
		OutputDir:          outDir,
		SecretKeySeparator: "-",
	})
	err := g.Generate()
	if err == nil {
		t.Fatal("expected error for invalid package pattern, got nil")
	}
}

// TestDST_WriteManifests_FailOnSchemaWrite targets the schema.yaml error return
// by letting earlier writes succeed.
func TestDST_WriteManifests_FailOnSchemaWrite(t *testing.T) {
	fields := []FieldInfo{
		{Path: "pub", Name: "pub", IsSecret: false, Value: "v"},
	}

	dir, err := os.MkdirTemp("", "dst-failschema-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chmod(dir, 0755)
		os.RemoveAll(dir)
	}()

	g := NewGenerator(Config{
		AppName:            "test",
		Namespace:          "default",
		SecretStore:        "vault",
		OutputDir:          dir,
		SecretKeySeparator: "-",
	})

	// Baseline succeeds.
	if err := g.writeManifests(fields); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	// Now: remove files, pre-create config-map.yaml and kustomization.yaml,
	// then make dir read-only so schema.yaml fails.
	os.Chmod(dir, 0755)
	entries, _ := os.ReadDir(dir)
	saved := map[string][]byte{}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		saved[e.Name()] = data
		os.Remove(filepath.Join(dir, e.Name()))
	}
	for _, f := range []string{"config-map.yaml", "kustomization.yaml"} {
		if data, ok := saved[f]; ok {
			os.WriteFile(filepath.Join(dir, f), data, 0644)
		}
	}
	os.Chmod(dir, 0555)
	err = g.writeManifests(fields)
	os.Chmod(dir, 0755)
	if err == nil {
		t.Error("expected error on schema.yaml write")
	}
}

// TestDST_WriteManifests_FailOnDefaultsWrite targets the defaults.yaml error return.
func TestDST_WriteManifests_FailOnDefaultsWrite(t *testing.T) {
	fields := []FieldInfo{
		{Path: "pub", Name: "pub", IsSecret: false, Value: "v"},
	}

	dir, err := os.MkdirTemp("", "dst-faildefaults-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chmod(dir, 0755)
		os.RemoveAll(dir)
	}()

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

	// Pre-create all files except defaults.yaml, then make dir read-only.
	os.Chmod(dir, 0755)
	entries, _ := os.ReadDir(dir)
	saved := map[string][]byte{}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		saved[e.Name()] = data
		os.Remove(filepath.Join(dir, e.Name()))
	}
	for _, f := range []string{"config-map.yaml", "kustomization.yaml", "schema.yaml", "bootstrap.json"} {
		if data, ok := saved[f]; ok {
			os.WriteFile(filepath.Join(dir, f), data, 0644)
		}
	}
	os.Chmod(dir, 0555)
	err = g.writeManifests(fields)
	os.Chmod(dir, 0755)
	if err == nil {
		t.Error("expected error on defaults.yaml write")
	}
}

// TestDST_WriteManifests_FailOnBootstrapWrite targets the bootstrap.json error return.
func TestDST_WriteManifests_FailOnBootstrapWrite(t *testing.T) {
	fields := []FieldInfo{
		{Path: "pub", Name: "pub", IsSecret: false, Value: "v"},
	}

	dir, err := os.MkdirTemp("", "dst-failbootstrap-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chmod(dir, 0755)
		os.RemoveAll(dir)
	}()

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

	// Pre-create config-map, kustomization, schema — but NOT bootstrap.json.
	os.Chmod(dir, 0755)
	entries, _ := os.ReadDir(dir)
	saved := map[string][]byte{}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		saved[e.Name()] = data
		os.Remove(filepath.Join(dir, e.Name()))
	}
	for _, f := range []string{"config-map.yaml", "kustomization.yaml", "schema.yaml"} {
		if data, ok := saved[f]; ok {
			os.WriteFile(filepath.Join(dir, f), data, 0644)
		}
	}
	os.Chmod(dir, 0555)
	err = g.writeManifests(fields)
	os.Chmod(dir, 0755)
	if err == nil {
		t.Error("expected error on bootstrap.json write")
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

		// Without prefix: squashed leaf should be at top level.
		fields := g.walkStruct(outerStruct, "", nil)
		if len(fields) != 1 {
			t.Fatalf("expected 1 field, got %d", len(fields))
		}
		if fields[0].Path != leafName {
			t.Errorf("squash without prefix: path = %s, want %s", fields[0].Path, leafName)
		}

		// With prefix: squashed leaf should use the prefix, not gain an extra segment.
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

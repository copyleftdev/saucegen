// Package main provides the saucegen command.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// structName is the name of the struct to parse (e.g., AppConfig).
	structName string
	// name is the base name for the generated resources.
	name string
	// namespace is the K8s namespace for the resources.
	namespace string
	// secretStore is the name of the SecretStore to use.
	secretStore string
	// valuesFile is the path to the config values file.
	valuesFile string
	// outputDir is the directory to output the manifests.
	outputDir string
	// configAsSecret indicates whether to generate ExternalSecret for public fields.
	configAsSecret bool
	// configStore is the SecretStore to use for public fields.
	configStore        string
	secretKeySeparator string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "saucegen",
		Short: "Generate K8s manifests from Go structs",
		Long:  "saucegen is a CLI tool that parses Go configuration structs and generates a bundle of Kubernetes manifests (ConfigMap, ExternalSecret) and a schema YAML file.",
	}

	var genCmd = &cobra.Command{
		Use:     "generate",
		Short:   "Generate resources",
		Aliases: []string{"gen"},
	}

	var k8sCmd = &cobra.Command{
		Use:   "k8s [package]",
		Short: "Generate K8s manifests for a package",
		Args:  cobra.ExactArgs(1),
		RunE:  runGenerate,
	}

	k8sCmd.Flags().StringVar(&structName, "struct", "AppConfig", "Name of the struct to parse")
	k8sCmd.Flags().StringVar(&name, "name", "app", "Base name for resources")
	k8sCmd.Flags().StringVar(&namespace, "namespace", "default", "Target namespace")
	k8sCmd.Flags().StringVar(&secretStore, "secret-store", "default", "SecretStore reference name")
	k8sCmd.Flags().StringVar(&valuesFile, "values", "", "Path to local config.yaml for default values")
	k8sCmd.Flags().StringVar(&outputDir, "output-dir", "./k8s/base", "Output directory")
	k8sCmd.Flags().BoolVar(&configAsSecret, "config-as-secret", false, "Generate ExternalSecret for public fields instead of ConfigMap")
	k8sCmd.Flags().StringVar(&configStore, "config-store", "default-config", "SecretStore reference for public config")
	k8sCmd.Flags().StringVar(&secretKeySeparator, "secret-key-separator", "-", "Separator between app name and secret key")

	genCmd.AddCommand(k8sCmd)

	rootCmd.AddCommand(genCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runGenerate executes the generation logic by initializing a Generator and calling Generate.
func runGenerate(cmd *cobra.Command, args []string) error {
	pkgPath := args[0]

	gen := NewGenerator(Config{
		PackagePath:        pkgPath,
		StructName:         structName,
		AppName:            name,
		Namespace:          namespace,
		SecretStore:        secretStore,
		ValuesFile:         valuesFile,
		OutputDir:          outputDir,
		ConfigAsSecret:     configAsSecret,
		ConfigStore:        configStore,
		SecretKeySeparator: secretKeySeparator,
	})

	return gen.Generate()
}

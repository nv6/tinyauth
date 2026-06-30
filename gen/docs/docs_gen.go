// gen/docs generates the .env.example and config.gen.md
// files for the configuration of Tinyauth. Run via:
//
// The generator reads the Tinyauth configuration package and using reflection it generates the
// example files. The .env.example is used in this repo while the config.gen.md is used in the
// documentaton alongside some warnings that are added later.
package main

import (
	"log/slog"
	"reflect"
)

func main() {
	slog.Info("generating example env file")
	generateExampleEnv()
	slog.Info("generating config reference markdown file")
	generateMarkdown()
}

func walkAndBuild[T any](parent reflect.Type, parentValue reflect.Value,
	parentPath string, entries *[]T,
	buildEntry func(child reflect.StructField, childValue reflect.Value, parentPath string, entries *[]T),
	buildMap func(child reflect.StructField, parentPath string, entries *[]T),
	buildChildPath func(parentPath string, childName string) string,
) {
	for i := 0; i < parent.NumField(); i++ {
		field := parent.Field(i)
		fieldType := field.Type
		fieldValue := parentValue.Field(i)

		switch fieldType.Kind() {
		case reflect.Struct:
			childPath := buildChildPath(parentPath, field.Name)
			walkAndBuild[T](fieldType, fieldValue, childPath, entries, buildEntry, buildMap, buildChildPath)
		case reflect.Map:
			buildMap(field, parentPath, entries)
		case reflect.Bool, reflect.String, reflect.Slice, reflect.Int:
			buildEntry(field, fieldValue, parentPath, entries)
		default:
			slog.Info("unknown type", "type", fieldType.Kind())
		}
	}
}

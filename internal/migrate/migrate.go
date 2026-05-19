package migrate

import (
	"context"
	"errors"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/sirupsen/logrus"
)

// migrateFile handles the file-level version migration logic
func migrateFile(file paasfile.File) error {
	_, err := file.GetPaas()
	if err != nil {
		return err
	}
	err = file.Write(context.TODO())
	if err != nil {
		return err
	}
	return nil
}

// Migrate converts the secrets of given PAAS from one version to another
func Migrate(files []string, outputFormat paasfile.Format) error {
	var errs []error
	for _, fileName := range files {
		file := paasfile.File{Path: fileName}
		if err := migrateFile(file); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		err := errors.Join(errs...)
		logrus.Errorf("finished with errors: %e", err)
		return err
	}
	logrus.Info("finished")
	return nil
}

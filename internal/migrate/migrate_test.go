package migrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/stubs/opr-paas/v1alpha1"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var _ = Describe("Migrate", Ordered, func() {
	var (
		tmpDir string
		v1Paas = v1alpha1.Paas{
			TypeMeta: metav1.TypeMeta{
				APIVersion: paasfile.V1Version,
				Kind:       "paas",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "v1paas",
				Labels: map[string]string{
					"some":  "label",
					"other": "label_too",
				},
			},
		}
		v2Paas = v1alpha2.Paas{
			TypeMeta: metav1.TypeMeta{
				APIVersion: paasfile.V2Version,
				Kind:       "paas",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "v2paas",
				Labels: map[string]string{
					"some":  "label",
					"other": "label_too",
				},
			},
		}
		allFiles []string
	)
	BeforeAll(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "migrate")
		Ω(err).Error().NotTo(HaveOccurred())
		ymlMFunc := func(v any) ([]byte, error) {
			return yaml.Marshal(v)
		}
		for version, paas := range map[string]any{
			"v1": v1Paas,
			"v2": v2Paas,
		} {
			for format, mFunc := range map[string]func(v any) ([]byte, error){
				"json": json.Marshal,
				"yaml": ymlMFunc,
			} {
				dump, err := mFunc(paas)
				Ω(err).Error().NotTo(HaveOccurred())
				filePath := path.Join(tmpDir, fmt.Sprintf("%s.%s", version, format))
				allFiles = append(allFiles, filePath)
				f, err := os.Create(filePath)
				Ω(err).Error().NotTo(HaveOccurred())
				_, err = f.Write(dump)
				Ω(err).Error().NotTo(HaveOccurred())
			}
		}
	})

	AfterAll(func() {
		err := os.RemoveAll(tmpDir)
		Ω(err).Error().NotTo(HaveOccurred())
	})

	When("Migrating a lot of files", func() {
		It("should succeed", func() {
			for _, filePath := range allFiles {
				fmt.Fprintf(GinkgoWriter, "DEBUG - migrating: %s\n", filePath)
				err := migrateFile(paasfile.File{Path: filePath}, paasfile.AutoFormat)
				Ω(err).Error().NotTo(HaveOccurred())
			}
		})
		It("should migrate all v1 files", func() {
			for _, path := range allFiles {
				contents, err := os.ReadFile(path)
				Ω(err).Error().NotTo(HaveOccurred())
				sContents := string(contents)
				Ω(sContents).NotTo(ContainSubstring(paasfile.V1Version))
				Ω(sContents).To(ContainSubstring(paasfile.V2Version))
			}
		})
	})
	When("Migrating improper files", func() {
		It("should fail", func() {
			var improper_files = map[string]string{
				"improper.toml": `apiVersion = cpet.belastingdienst.nl/v1alpha1
kind = Paas
[metadata]
  name = tst-tst
[spec]`,
				"invalid.json": `{"apiVersion": "cpet.belastingdienst.nl/v1alpha1","kind": "Paas","metadata": ` +
					`{"name": "tst-tst"},"spec": null`,
				"invalid.version": `{"apiVersion": "cpet.belastingdienst.nl/v1alpha3","kind": "Paas","metadata": ` +
					`{"name": "tst-tst"},"spec": null}`,
				"invalid.kind": `{"apiVersion": "cpet.belastingdienst.nl/v1alpha3","kind": "Paasje","metadata": ` +
					`{"name": "tst-tst"},"spec": null}`,
			}
			for name, contents := range improper_files {
				filePath := path.Join(tmpDir, name)
				f, err := os.Create(filePath)
				Ω(err).Error().NotTo(HaveOccurred())
				_, err = f.Write([]byte(contents))
				Ω(err).Error().NotTo(HaveOccurred())
				err = migrateFile(paasfile.File{Path: filePath}, paasfile.AutoFormat)
				Ω(err).Error().To(HaveOccurred())
			}
		})
	})
})

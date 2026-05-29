package utils

import (
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PathToFileList", Ordered, func() {
	const (
		fileModeUserReadWrite = 0o600
		dirModeUserReadWrite  = 0o700
	)
	var (
		orgTempDir         string
		unsymlinkedTempDir string
		absoluteTempDir    string
	)
	BeforeAll(func() {
		var err error
		orgTempDir, err = os.MkdirTemp("", "utils_test")
		Ω(err).Error().NotTo(HaveOccurred())
		unsymlinkedTempDir, err = filepath.EvalSymlinks(orgTempDir)
		Ω(err).Error().NotTo(HaveOccurred())
		absoluteTempDir, err = filepath.Abs(unsymlinkedTempDir)
		Ω(err).Error().NotTo(HaveOccurred())
	})
	AfterAll(func() {
		os.RemoveAll(orgTempDir)
	})
	When("Getting a list from Path", Ordered, func() {
		It("should evaluate a file", func() {
			const fileName = "regular"
			filePath := filepath.Join(absoluteTempDir, fileName)
			Ω(os.WriteFile(filePath, []byte("something"), fileModeUserReadWrite)).Error().NotTo(HaveOccurred())
			files, err := PathToFileList([]string{filePath})
			Ω(err).Error().NotTo(HaveOccurred())
			Ω(files).To(HaveLen(1))
			Ω(files).To(ContainElement(Equal(filePath)))
		})
		It("should evaluate a folder with files", func() {
			const folderName = "folder"
			var testFiles []string
			folderPath := filepath.Join(absoluteTempDir, folderName)
			err := os.Mkdir(folderPath, dirModeUserReadWrite)
			Ω(err).Error().NotTo(HaveOccurred())

			for i := 0; i < 3; i++ {
				filePath := filepath.Join(folderPath, fmt.Sprintf("%d", i))
				err := os.WriteFile(filePath, []byte("something"), fileModeUserReadWrite)
				Ω(err).Error().NotTo(HaveOccurred())
				testFiles = append(testFiles, filePath)
			}

			files, err := PathToFileList([]string{folderPath})
			Ω(err).Error().NotTo(HaveOccurred())
			Ω(files).To(HaveLen(len(testFiles)))
			for _, filePath := range testFiles {
				Ω(files).To(ContainElement(Equal(filePath)))
			}
		})
		It("should evaluate a symlink", func() {
			const (
				linkedName = "linked"
				linkName   = "link"
			)
			linkPath := filepath.Join(absoluteTempDir, linkName)
			linkedPath := filepath.Join(absoluteTempDir, linkedName)
			err := os.WriteFile(linkedPath, []byte("something"), fileModeUserReadWrite)
			Ω(err).Error().NotTo(HaveOccurred())
			err = os.Symlink(linkedPath, linkPath)
			Ω(err).Error().NotTo(HaveOccurred())
			files, err := PathToFileList([]string{linkPath})
			Ω(err).Error().NotTo(HaveOccurred())
			Ω(files).To(HaveLen(1))
			Ω(files).To(ContainElement(Equal(linkedPath)))
		})
		It("should evaluate a folder sub-sub-sub-folder with a file", func() {
			const folderName = "sub-sub-sub"
			folderPath := filepath.Join(absoluteTempDir, folderName)
			err := os.Mkdir(folderPath, dirModeUserReadWrite)
			Ω(err).Error().NotTo(HaveOccurred())

			subdir := folderPath
			for i := 0; i < 3; i++ {
				subdir = filepath.Join(subdir, fmt.Sprintf("%d", i))
				err := os.Mkdir(subdir, dirModeUserReadWrite)
				Ω(err).Error().NotTo(HaveOccurred())
			}
			filePath := filepath.Join(subdir, "file")
			Ω(os.WriteFile(filePath, []byte("something"), fileModeUserReadWrite)).Error().NotTo(HaveOccurred())

			files, err := PathToFileList([]string{folderPath})
			Ω(err).Error().NotTo(HaveOccurred())
			Ω(files).To(HaveLen(1))
			Ω(files).To(ContainElement(Equal(filePath)))
		})
		/*
			It("should check for readability", func() {
			})
			It("should break on symlink issues", func() {
			})
			It("should return absolute path", func() {
			})
			It("should break when it does not get the stat", func() {
			})
			It("should only return regular files", func() {
			})
		*/
	})
})

// revive:disable:line-length-limit
var _ = Describe("HashData", func() {
	const (
		nilHash   = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
		allchars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		superLong = allchars + allchars + allchars + allchars + allchars + allchars + allchars + allchars + allchars + allchars
	)
	When("Hashing data", Ordered, func() {
		It("should succeed", func() {
			for _, test := range []struct {
				in       []byte
				expected string
			}{
				{in: nil, expected: nilHash},
				{in: []byte(""), expected: nilHash},
				{in: []byte("my-paas"), expected: "d1e6a79f54dc1294bcb0bc7e254aeb9c53b741e95e01924bebf7c9fb4788b185beaa038ba25ef02c902da9c9f2675b9ffedab45e1d5d86b609373db140ded12b"},
				{in: []byte("something"), expected: "983d43ddff6da90f6a5d3b6172446a1ffe228b803fe64fdd5dcfab5646078a896851fe82f623c9d6e5654b3d2f363a04ec17cfb62b607437a9c7c132d511e522"},
				{in: []byte(allchars), expected: "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894"},
				{in: []byte(superLong)[0 : len(superLong)-1], expected: "7eeb4426cb86ccd73ecaf81cbca92417f4d347ca20da96d57d81116ba9fed04a80e827cb17caea86a1937c742c266422abcce3a94699dc6fd4d52a99b3e45197"},
			} {
				out := HashData(test.in)
				Ω(out).To(Equal(test.expected))
			}
		})
	})
})

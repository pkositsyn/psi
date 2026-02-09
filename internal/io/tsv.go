package io

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

var EOF = io.EOF

type TSVReader struct {
	reader *csv.Reader
	rc     io.ReadCloser
}

func NewTSVReader(rc io.ReadCloser) *TSVReader {
	return &TSVReader{
		reader: createCSVReader(rc),
		rc:     rc,
	}
}

func OpenTSVFile(filename string) (*TSVReader, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	var reader io.ReadCloser = file

	if strings.HasSuffix(filename, ".gz") {
		gzr, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		reader = &gzipReadCloser{gzr, file}
	}

	return NewTSVReader(reader), nil
}

type gzipReadCloser struct {
	gzipReader *gzip.Reader
	file       *os.File
}

func (g *gzipReadCloser) Read(p []byte) (int, error) {
	return g.gzipReader.Read(p)
}

func (g *gzipReadCloser) Close() error {
	g.gzipReader.Close()
	return g.file.Close()
}

func createCSVReader(r io.Reader) *csv.Reader {
	reader := csv.NewReader(r)
	reader.Comma = '\t'
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	return reader
}

func (r *TSVReader) Read() ([]string, error) {
	return r.reader.Read()
}

func (r *TSVReader) Close() error {
	return r.rc.Close()
}

type TSVWriter struct {
	writer *csv.Writer
	wc     io.WriteCloser
}

func NewTSVWriter(wc io.WriteCloser) *TSVWriter {
	return &TSVWriter{
		writer: createCSVWriter(wc),
		wc:     wc,
	}
}

func CreateTSVFile(filename string) (*TSVWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	var writer io.WriteCloser = file

	if strings.HasSuffix(filename, ".gz") {
		gzw := gzip.NewWriter(file)
		writer = &gzipWriteCloser{gzw, file}
	}

	return NewTSVWriter(writer), nil
}

type gzipWriteCloser struct {
	gzipWriter *gzip.Writer
	file       *os.File
}

func (g *gzipWriteCloser) Write(p []byte) (int, error) {
	return g.gzipWriter.Write(p)
}

func (g *gzipWriteCloser) Close() error {
	if err := g.gzipWriter.Close(); err != nil {
		g.file.Close()
		return err
	}
	return g.file.Close()
}

func createCSVWriter(w io.Writer) *csv.Writer {
	writer := csv.NewWriter(w)
	writer.Comma = '\t'
	return writer
}

func (w *TSVWriter) Write(record []string) error {
	return w.writer.Write(record)
}

func (w *TSVWriter) Flush() error {
	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		return fmt.Errorf("ошибка записи CSV: %w", err)
	}
	return nil
}

func (w *TSVWriter) Close() error {
	if err := w.Flush(); err != nil {
		return err
	}
	return w.wc.Close()
}

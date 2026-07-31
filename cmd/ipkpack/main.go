package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func add(w *tar.Writer, root, path string, mode func(string) int64) error {
	info, e := os.Stat(path)
	if e != nil {
		return e
	}
	n, _ := filepath.Rel(root, path)
	n = filepath.ToSlash(n)
	h, _ := tar.FileInfoHeader(info, "")
	h.Name = n
	if info.IsDir() {
		h.Mode = 0755
	} else {
		h.Mode = mode(n)
	}
	if e = w.WriteHeader(h); e != nil {
		return e
	}
	if info.IsDir() {
		xs, _ := os.ReadDir(path)
		for _, x := range xs {
			if e := add(w, root, filepath.Join(path, x.Name()), mode); e != nil {
				return e
			}
		}
	} else {
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		_, e = io.Copy(w, f)
		return e
	}
	return nil
}
func archive(out, root string, mode func(string) int64) error {
	f, e := os.Create(out)
	if e != nil {
		return e
	}
	defer f.Close()
	g := gzip.NewWriter(f)
	defer g.Close()
	w := tar.NewWriter(g)
	defer w.Close()
	xs, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	for _, x := range xs {
		if e := add(w, root, filepath.Join(root, x.Name()), mode); e != nil {
			return e
		}
	}
	return nil
}
func main() {
	out := flag.String("out", "", "output ipk")
	pkg := flag.String("pkg", "", "package directory")
	flag.Parse()
	if e := archive(filepath.Join(*pkg, "control.tar.gz"), filepath.Join(*pkg, "control"), func(n string) int64 {
		if strings.HasSuffix(n, "preinst") || strings.HasSuffix(n, "postinst") || strings.HasSuffix(n, "prerm") || strings.HasSuffix(n, "postrm") {
			return 0755
		}
		return 0644
	}); e != nil {
		panic(e)
	}
	if e := archive(filepath.Join(*pkg, "data.tar.gz"), filepath.Join(*pkg, "data"), func(n string) int64 {
		if strings.HasSuffix(n, "qwdtt") ||
			strings.HasSuffix(n, "S99qwdtt") ||
			strings.HasSuffix(n, "60-qwdtt-netfilter.sh") {
			return 0755
		}
		return 0644
	}); e != nil {
		panic(e)
	}
	f, e := os.Create(*out)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	g := gzip.NewWriter(f)
	defer g.Close()
	w := tar.NewWriter(g)
	defer w.Close()
	for _, n := range []string{"debian-binary", "control.tar.gz", "data.tar.gz"} {
		p := filepath.Join(*pkg, n)
		i, _ := os.Stat(p)
		h, _ := tar.FileInfoHeader(i, "")
		h.Name = n
		h.Mode = 0644
		w.WriteHeader(h)
		x, _ := os.Open(p)
		io.Copy(w, x)
		x.Close()
	}
}

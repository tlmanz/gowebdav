package gowebdav

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	pathpkg "path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/webdav"
)

func noAuthHndl(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}
}

func basicAuth(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if user, passwd, ok := r.BasicAuth(); ok {
			if user == "user" && passwd == "password" {
				h.ServeHTTP(w, r)
				return
			}

			http.Error(w, "not authorized", 403)
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
		}
	}
}

func basicAuthWithPostHandlerFunc(h http.Handler, postHandlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, passwd, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
			return
		}

		if user != "user" || passwd != "password" {
			http.Error(w, "not authorized", 403)
			return
		}

		h.ServeHTTP(w, r)
		postHandlerFunc(w, r)
	}
}

func multipleAuth(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		notAuthed := false
		if r.Header.Get("Authorization") == "" {
			notAuthed = true
		} else if user, passwd, ok := r.BasicAuth(); ok {
			if user == "user" && passwd == "password" {
				h.ServeHTTP(w, r)
				return
			}
			notAuthed = true
		} else if strings.HasPrefix(r.Header.Get("Authorization"), "Digest ") {
			pairs := strings.TrimPrefix(r.Header.Get("Authorization"), "Digest ")
			digestParts := make(map[string]string)
			for _, pair := range strings.Split(pairs, ",") {
				kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
				key, value := kv[0], kv[1]
				value = strings.Trim(value, `"`)
				digestParts[key] = value
			}
			if digestParts["qop"] == "" {
				digestParts["qop"] = "auth"
			}

			ha1 := getMD5(fmt.Sprint(digestParts["username"], ":", digestParts["realm"], ":", "digestPW"))
			ha2 := getMD5(fmt.Sprint(r.Method, ":", digestParts["uri"]))
			expected := getMD5(fmt.Sprint(ha1,
				":", digestParts["nonce"],
				":", digestParts["nc"],
				":", digestParts["cnonce"],
				":", digestParts["qop"],
				":", ha2))

			if expected == digestParts["response"] {
				h.ServeHTTP(w, r)
				return
			}
			notAuthed = true
		}

		if notAuthed {
			w.Header().Add("WWW-Authenticate", `Digest realm="testrealm@host.com", qop="auth,auth-int",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",opaque="5ccc069c403ebaf9f0171e9517f40e41"`)
			w.Header().Add("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(401)
		}
	}
}

func fillFs(t *testing.T, fs webdav.FileSystem) context.Context {
	ctx := context.Background()
	f, err := fs.OpenFile(ctx, "hello.txt", os.O_CREATE, 0644)
	if err != nil {
		t.Errorf("fail to crate file: %v", err)
	}
	f.Write([]byte("hello gowebdav\n"))
	f.Close()
	err = fs.Mkdir(ctx, "/test", 0755)
	if err != nil {
		t.Errorf("fail to crate directory: %v", err)
	}
	f, err = fs.OpenFile(ctx, "/test/test.txt", os.O_CREATE, 0644)
	if err != nil {
		t.Errorf("fail to crate file: %v", err)
	}
	f.Write([]byte("test test gowebdav\n"))
	f.Close()
	return ctx
}

func newServer(t *testing.T) (*Client, *httptest.Server, webdav.FileSystem, context.Context) {
	return newAuthServer(t, basicAuth)
}

func newAuthServer(t *testing.T, auth func(h http.Handler) http.HandlerFunc) (*Client, *httptest.Server, webdav.FileSystem, context.Context) {
	srv, fs, ctx := newAuthSrv(t, auth)
	cli := NewClient(srv.URL, "user", "password")
	return cli, srv, fs, ctx
}

func newAuthSrv(t *testing.T, auth func(h http.Handler) http.HandlerFunc) (*httptest.Server, webdav.FileSystem, context.Context) {
	mux := http.NewServeMux()
	fs := webdav.NewMemFS()
	ctx := fillFs(t, fs)
	mux.HandleFunc("/", auth(&webdav.Handler{
		FileSystem: fs,
		LockSystem: webdav.NewMemLS(),
	}))
	srv := httptest.NewServer(mux)
	return srv, fs, ctx
}

func newAuthServerAcquireContentLength(t *testing.T) (*Client, *httptest.Server, webdav.FileSystem, context.Context) {
	srv, fs, ctx := newAuthSrvAcquireContentLength(t, basicAuthWithPostHandlerFunc)
	cli := NewClient(srv.URL, "user", "password")
	return cli, srv, fs, ctx
}

func newAuthSrvAcquireContentLength(t *testing.T, authWithPostHandlerFunc func(h http.Handler, postHandlerFunc http.HandlerFunc) http.HandlerFunc) (*httptest.Server, webdav.FileSystem, context.Context) {
	mux := http.NewServeMux()
	fs := webdav.NewMemFS()
	ctx := fillFs(t, fs)
	mux.HandleFunc("/", authWithPostHandlerFunc(&webdav.Handler{
		FileSystem: fs,
		LockSystem: webdav.NewMemLS(),
	}, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			return
		}

		fileName := strings.TrimPrefix(r.URL.Path, "/")
		stat, err := fs.Stat(ctx, fileName)
		if err != nil {
			t.Fatalf("got: %v, want nil", err)
		}

		if r.ContentLength != stat.Size() {
			t.Fatalf("acquire content length got: %v, want %v", r.ContentLength, stat.Size())
		}
	}))
	srv := httptest.NewServer(mux)
	return srv, fs, ctx
}

func TestConnect(t *testing.T) {
	cli, srv, _, _ := newServer(t)
	defer srv.Close()
	if err := cli.Connect(); err != nil {
		t.Fatalf("got error: %v, want nil", err)
	}

	cli = NewClient(srv.URL, "no", "no")
	if err := cli.Connect(); err == nil {
		t.Fatalf("got nil, want error: %v", err)
	}
}

func TestConnectMultipleAuth(t *testing.T) {
	cli, srv, _, _ := newAuthServer(t, multipleAuth)
	defer srv.Close()
	if err := cli.Connect(); err != nil {
		t.Fatalf("got error: %v, want nil", err)
	}

	cli = NewClient(srv.URL, "digestUser", "digestPW")
	if err := cli.Connect(); err != nil {
		t.Fatalf("got nil, want error: %v", err)
	}

	cli = NewClient(srv.URL, "no", "no")
	if err := cli.Connect(); err == nil {
		t.Fatalf("got nil, want error: %v", err)
	}
}

func TestConnectMultiAuthII(t *testing.T) {
	cli, srv, _, _ := newAuthServer(t, func(h http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if user, passwd, ok := r.BasicAuth(); ok {
				if user == "user" && passwd == "password" {
					h.ServeHTTP(w, r)
					return
				}

				http.Error(w, "not authorized", 403)
			} else {
				w.Header().Add("WWW-Authenticate", `FooAuth`)
				w.Header().Add("WWW-Authenticate", `BazAuth`)
				w.Header().Add("WWW-Authenticate", `BarAuth`)
				w.Header().Add("WWW-Authenticate", `Basic realm="x"`)
				w.WriteHeader(401)
			}
		}
	})
	defer srv.Close()
	if err := cli.Connect(); err != nil {
		t.Fatalf("got error: %v, want nil", err)
	}

	cli = NewClient(srv.URL, "no", "no")
	if err := cli.Connect(); err == nil {
		t.Fatalf("got nil, want error: %v", err)
	}
}

func TestReadDirConcurrent(t *testing.T) {
	cli, srv, _, _ := newServer(t)
	defer srv.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			f, err := cli.ReadDir("/")
			if err != nil {
				errs <- errors.New(fmt.Sprintf("got error: %v, want file listing: %v", err, f))
			}
			if len(f) != 2 {
				errs <- errors.New(fmt.Sprintf("f: %v err: %v", f, err))
			}
			if f[0].Name() != "hello.txt" && f[1].Name() != "hello.txt" {
				errs <- errors.New(fmt.Sprintf("got: %v, want file: %s", f, "hello.txt"))
			}
			if f[0].Name() != "test" && f[1].Name() != "test" {
				errs <- errors.New(fmt.Sprintf("got: %v, want directory: %s", f, "test"))
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRead(t *testing.T) {
	cli, srv, _, _ := newServer(t)
	defer srv.Close()

	data, err := cli.Read("/hello.txt")
	if err != nil || bytes.Compare(data, []byte("hello gowebdav\n")) != 0 {
		t.Fatalf("got: %v, want data: %s", err, []byte("hello gowebdav\n"))
	}

	data, err = cli.Read("/404.txt")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", data, err)
	}
	if !IsErrNotFound(err) {
		t.Fatalf("got: %v, want 404 error", err)
	}
}

func TestReadNoAuth(t *testing.T) {
	cli, srv, _, _ := newAuthServer(t, noAuthHndl)
	defer srv.Close()

	data, err := cli.Read("/hello.txt")
	if err != nil || bytes.Compare(data, []byte("hello gowebdav\n")) != 0 {
		t.Fatalf("got: %v, want data: %s", err, []byte("hello gowebdav\n"))
	}

	data, err = cli.Read("/404.txt")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", data, err)
	}
	if !IsErrNotFound(err) {
		t.Fatalf("got: %v, want 404 error", err)
	}
}

func TestReadStream(t *testing.T) {
	cli, srv, _, _ := newServer(t)
	defer srv.Close()

	stream, err := cli.ReadStream("/hello.txt")
	if err != nil {
		t.Fatalf("got: %v, want data: %v", err, stream)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	if buf.String() != "hello gowebdav\n" {
		t.Fatalf("got: %v, want stream: hello gowebdav", buf.String())
	}

	stream, err = cli.ReadStream("/404/hello.txt")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", stream, err)
	}
}

func TestReadStreamRange(t *testing.T) {
	cli, srv, _, _ := newServer(t)
	defer srv.Close()

	stream, err := cli.ReadStreamRange("/hello.txt", 4, 4)
	if err != nil {
		t.Fatalf("got: %v, want data: %v", err, stream)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	if buf.String() != "o go" {
		t.Fatalf("got: %v, want stream: o go", buf.String())
	}

	stream, err = cli.ReadStream("/404/hello.txt")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", stream, err)
	}
}

func TestReadStreamRangeUnkownLength(t *testing.T) {
	cli, srv, _, _ := newServer(t)
	defer srv.Close()

	stream, err := cli.ReadStreamRange("/hello.txt", 6, 0)
	if err != nil {
		t.Fatalf("got: %v, want data: %v", err, stream)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	if buf.String() != "gowebdav\n" {
		t.Fatalf("got: %v, want stream: gowebdav\n", buf.String())
	}

	stream, err = cli.ReadStream("/404/hello.txt")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", stream, err)
	}
}

func TestStat(t *testing.T) {
	cli, srv, _, _ := newServer(t)
	defer srv.Close()

	info, err := cli.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("got: %v, want os.Info: %v", err, info)
	}
	if info.Name() != "hello.txt" {
		t.Fatalf("got: %v, want file hello.txt", info)
	}

	info, err = cli.Stat("/404.txt")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", info, err)
	}
	if !IsErrNotFound(err) {
		t.Fatalf("got: %v, want 404 error", err)
	}
}

func TestMkdir(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	info, err := cli.Stat("/newdir")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", info, err)
	}

	if err := cli.Mkdir("/newdir", 0755); err != nil {
		t.Fatalf("got: %v, want mkdir /newdir", err)
	}

	if err := cli.Mkdir("/newdir", 0755); err != nil {
		t.Fatalf("got: %v, want mkdir /newdir", err)
	}

	info, err = fs.Stat(ctx, "/newdir")
	if err != nil {
		t.Fatalf("got: %v, want dir info: %v", err, info)
	}

	if err := cli.Mkdir("/404/newdir", 0755); err == nil {
		t.Fatalf("expected Mkdir error due to missing parent directory")
	}
}

func TestMkdirAll(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	if err := cli.MkdirAll("/dir/dir/dir", 0755); err != nil {
		t.Fatalf("got: %v, want mkdirAll /dir/dir/dir", err)
	}

	info, err := fs.Stat(ctx, "/dir/dir/dir")
	if err != nil {
		t.Fatalf("got: %v, want dir info: %v", err, info)
	}
}

func TestCopy(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	info, err := fs.Stat(ctx, "/copy.txt")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", info, err)
	}

	if err := cli.Copy("/hello.txt", "/copy.txt", false); err != nil {
		t.Fatalf("got: %v, want copy /hello.txt to /copy.txt", err)
	}

	info, err = fs.Stat(ctx, "/copy.txt")
	if err != nil {
		t.Fatalf("got: %v, want file info: %v", err, info)
	}
	if info.Size() != 15 {
		t.Fatalf("got: %v, want file size: %d bytes", info.Size(), 15)
	}

	info, err = fs.Stat(ctx, "/hello.txt")
	if err != nil {
		t.Fatalf("got: %v, want file info: %v", err, info)
	}
	if info.Size() != 15 {
		t.Fatalf("got: %v, want file size: %d bytes", info.Size(), 15)
	}

	if err := cli.Copy("/hello.txt", "/copy.txt", false); err == nil {
		t.Fatalf("expected copy error due to overwrite false")
	}

	if err := cli.Copy("/hello.txt", "/copy.txt", true); err != nil {
		t.Fatalf("got: %v, want overwrite /copy.txt with /hello.txt", err)
	}
}

func TestRename(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	info, err := fs.Stat(ctx, "/copy.txt")
	if err == nil {
		t.Fatalf("got: %v, want error: %v", info, err)
	}

	if err := cli.Rename("/hello.txt", "/copy.txt", false); err != nil {
		t.Fatalf("got: %v, want mv /hello.txt to /copy.txt", err)
	}

	info, err = fs.Stat(ctx, "/copy.txt")
	if err != nil {
		t.Fatalf("got: %v, want file info: %v", err, info)
	}
	if info.Size() != 15 {
		t.Fatalf("got: %v, want file size: %d bytes", info.Size(), 15)
	}

	if info, err = fs.Stat(ctx, "/hello.txt"); err == nil {
		t.Fatalf("got: %v, want error: %v", info, err)
	}

	if err := cli.Rename("/test/test.txt", "/copy.txt", true); err != nil {
		t.Fatalf("got: %v, want overwrite /copy.txt with /hello.txt", err)
	}
	info, err = fs.Stat(ctx, "/copy.txt")
	if err != nil {
		t.Fatalf("got: %v, want file info: %v", err, info)
	}
	if info.Size() != 19 {
		t.Fatalf("got: %v, want file size: %d bytes", info.Size(), 19)
	}
}

func TestRemove(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	if err := cli.Remove("/hello.txt"); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	if info, err := fs.Stat(ctx, "/hello.txt"); err == nil {
		t.Fatalf("got: %v, want error: %v", info, err)
	}

	if err := cli.Remove("/404.txt"); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}
}

func TestRemoveAll(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	if err := cli.RemoveAll("/test/test.txt"); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	if info, err := fs.Stat(ctx, "/test/test.txt"); err == nil {
		t.Fatalf("got: %v, want error: %v", info, err)
	}

	if err := cli.RemoveAll("/404.txt"); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	if err := cli.RemoveAll("/404/404/404.txt"); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}
}

func TestWrite(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	if err := cli.Write("/newfile.txt", []byte("foo bar\n"), 0660); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	info, err := fs.Stat(ctx, "/newfile.txt")
	if err != nil {
		t.Fatalf("got: %v, want file info: %v", err, info)
	}
	if info.Size() != 8 {
		t.Fatalf("got: %v, want file size: %d bytes", info.Size(), 8)
	}

	if err := cli.Write("/404/newfile.txt", []byte("foo bar\n"), 0660); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}
}

func TestWriteStream(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	if err := cli.WriteStream("/newfile.txt", strings.NewReader("foo bar\n"), 0660); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	info, err := fs.Stat(ctx, "/newfile.txt")
	if err != nil {
		t.Fatalf("got: %v, want file info: %v", err, info)
	}
	if info.Size() != 8 {
		t.Fatalf("got: %v, want file size: %d bytes", info.Size(), 8)
	}

	if err := cli.WriteStream("/404/works.txt", strings.NewReader("foo bar\n"), 0660); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	if info, err := fs.Stat(ctx, "/404/works.txt"); err != nil {
		t.Fatalf("got: %v, want file info: %v", err, info)
	}
}

func TestWriteStreamFromPipe(t *testing.T) {
	cli, srv, fs, ctx := newServer(t)
	defer srv.Close()

	r, w := io.Pipe()

	go func() {
		defer w.Close()
		fmt.Fprint(w, "foo")
		time.Sleep(1 * time.Second)
		fmt.Fprint(w, " ")
		time.Sleep(1 * time.Second)
		fmt.Fprint(w, "bar\n")
	}()

	if err := cli.WriteStream("/newfile.txt", r, 0660); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	info, err := fs.Stat(ctx, "/newfile.txt")
	if err != nil {
		t.Fatalf("got: %v, want file info: %v", err, info)
	}
	if info.Size() != 8 {
		t.Fatalf("got: %v, want file size: %d bytes", info.Size(), 8)
	}
}

func TestWriteToServerAcquireContentLength(t *testing.T) {
	cli, srv, _, _ := newAuthServerAcquireContentLength(t)
	defer srv.Close()

	if err := cli.Write("/newfile.txt", []byte("foo bar\n"), 0660); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}
}

func TestWriteStreamToServerAcquireContentLength(t *testing.T) {
	cli, srv, _, _ := newAuthServerAcquireContentLength(t)
	defer srv.Close()

	if err := cli.WriteStream("/newfile.txt", strings.NewReader("foo bar\n"), 0660); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	lf := make([]byte, 10*1024*1024)
	rand.Read(lf)
	if err := cli.WriteStream("/largefile.bin", bytes.NewBuffer(lf), 0660); err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	lf2, err := cli.Read("/largefile.bin")
	if err != nil {
		t.Fatalf("got: %v, want nil", err)
	}

	if !bytes.Equal(lf, lf2) {
		t.Fatalf("%s largefile.bin doesn't match", t.Name())
	}
}

func TestNextcloudChunkedUpload(t *testing.T) {
	// Simulate minimal Nextcloud chunk API endpoints under /remote.php/dav/uploads/<user>/ and files/<user>/
	user := "user"
	mux := http.NewServeMux()
	fs := webdav.NewMemFS()
	lcks := webdav.NewMemLS()

	uploads := make(map[string][]byte)

	// Handle MKCOL and PUT under uploads prefix
	mux.HandleFunc("/remote.php/dav/uploads/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /remote.php/dav/uploads/<user>/<folder>/[chunk-name or .file]
		if r.Method == "MKCOL" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == http.MethodPut {
			// store chunk content by request path
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			uploads[r.URL.Path] = b
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == "MOVE" {
			// Assemble chunks by sorting keys starting with folder path (excluding .file path itself)
			dest := r.Header.Get("Destination")
			if dest == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// gather chunks
			folder := strings.TrimSuffix(r.URL.Path, "/.file")
			// concatenate in lexical order
			var keys []string
			for k := range uploads {
				if strings.HasPrefix(k, folder+"/") {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			var data []byte
			for _, k := range keys {
				data = append(data, uploads[k]...)
			}

			// write to files area dest path
			du, _ := neturl.Parse(dest)
			// map dest into local fs by trimming server origin, assume same server root
			target := strings.TrimPrefix(du.Path, "/remote.php/dav/files/")
			ctx := context.Background()
			if err := fs.Mkdir(ctx, pathpkg.Dir(target), 0755); err != nil && !os.IsExist(err) {
				t.Fatalf("mkdir: %v", err)
			}
			f, err := fs.OpenFile(ctx, target, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if _, err := f.Write(data); err != nil {
				t.Fatalf("write: %v", err)
			}
			f.Close()
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// Files namespace served by webdav handler for readback
	mux.Handle("/remote.php/dav/files/", http.StripPrefix("/remote.php/dav/files/", &webdav.Handler{FileSystem: fs, LockSystem: lcks}))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cli := NewClient(srv.URL+"/remote.php/dav", "", "")

	content := bytes.Repeat([]byte("A"), 2*1024*1024+123) // >2MB to force multiple chunks
	// Upload via chunked API with 1MB chunks
	err := cli.WriteStreamNextcloudChunked(srv.URL+"/remote.php/dav/uploads/"+user+"/", srv.URL+"/remote.php/dav/files/"+user+"/chunked.bin", bytes.NewReader(content), 1*1024*1024, 0)
	if err != nil {
		t.Fatalf("chunked upload failed: %v", err)
	}

	// Read back using normal client
	data, err := cli.Read("/files/" + user + "/chunked.bin")
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("uploaded content mismatch: got %d bytes, want %d", len(data), len(content))
	}
}

func TestNextcloudChunkedUploadAuto(t *testing.T) {
	// Same simulated Nextcloud endpoints as previous test
	user := "user"
	mux := http.NewServeMux()
	fs := webdav.NewMemFS()
	lcks := webdav.NewMemLS()

	uploads := make(map[string][]byte)

	mux.HandleFunc("/remote.php/dav/uploads/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "MKCOL" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == http.MethodPut {
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			uploads[r.URL.Path] = b
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == "MOVE" {
			dest := r.Header.Get("Destination")
			if dest == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			folder := strings.TrimSuffix(r.URL.Path, "/.file")
			var keys []string
			for k := range uploads {
				if strings.HasPrefix(k, folder+"/") {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			var data []byte
			for _, k := range keys {
				data = append(data, uploads[k]...)
			}

			du, _ := neturl.Parse(dest)
			target := strings.TrimPrefix(du.Path, "/remote.php/dav/files/")
			ctx := context.Background()
			if err := fs.Mkdir(ctx, pathpkg.Dir(target), 0755); err != nil && !os.IsExist(err) {
				t.Fatalf("mkdir: %v", err)
			}
			f, err := fs.OpenFile(ctx, target, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if _, err := f.Write(data); err != nil {
				t.Fatalf("write: %v", err)
			}
			f.Close()
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	mux.Handle("/remote.php/dav/files/", http.StripPrefix("/remote.php/dav/files/", &webdav.Handler{FileSystem: fs, LockSystem: lcks}))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cli := NewClient(srv.URL+"/remote.php/dav", "", "")

	content := bytes.Repeat([]byte("B"), 1024*1024+777) // ~1MB +
	// Destination as DAV path under /files/<user>/..., auto should derive uploads URL and absolute dest
	dest := "/files/" + user + "/chunked_auto.bin"
	if err := cli.WriteStreamNextcloudChunkedAuto(dest, bytes.NewReader(content), 512*1024, 0); err != nil {
		t.Fatalf("chunked auto upload failed: %v", err)
	}

	data, err := cli.Read(dest)
	if err != nil {
		t.Fatalf("read back auto failed: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("uploaded content mismatch: got %d bytes, want %d", len(data), len(content))
	}
}

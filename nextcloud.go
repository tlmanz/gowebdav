package gowebdav

import (
    "bytes"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    pathpkg "path"
    "strconv"
)

// NextcloudChunkedUpload provides helpers to use Nextcloud's chunking API.
// See: https://docs.nextcloud.com/server/20/developer_manual/client_apis/WebDAV/chunking.html
type NextcloudChunkedUpload struct {
    c         *Client
    UploadURL string // absolute URL of the upload collection (uploads/<user>/<folder>)
    Folder    string // unique folder name under uploads/<user>
}

// Start creates a unique upload folder under the uploads namespace.
// baseUploadURL is typically: <server>/remote.php/dav/uploads/<userid>
func (n *NextcloudChunkedUpload) Start(baseUploadURL string) error {
    n.UploadURL = FixSlash(baseUploadURL)
    if n.Folder == "" {
        // generate random hex folder name
        b := make([]byte, 16)
        if _, err := rand.Read(b); err != nil {
            return err
        }
        n.Folder = hex.EncodeToString(b)
    }
    // MKCOL to create the folder
    rs, err := n.c.req("MKCOL", n.UploadURL+n.Folder, nil, nil)
    if err != nil {
        return err
    }
    io.Copy(io.Discard, rs.Body)
    rs.Body.Close()
    if rs.StatusCode != http.StatusCreated && rs.StatusCode != http.StatusMethodNotAllowed {
        // 405 means already exists; allow reuse to resume
        return NewPathError("MKCOL", n.UploadURL+n.Folder, rs.StatusCode)
    }
    return nil
}

// UploadChunk uploads a single chunk with name start-end (zero padded) as required by Nextcloud docs.
func (n *NextcloudChunkedUpload) UploadChunk(start, end int64, r io.Reader, size int64) error {
    name := fmt.Sprintf("%015d-%015d", start, end)
    rs, err := n.c.req("PUT", n.UploadURL+n.Folder+"/"+name, r, func(req *http.Request) {
        req.ContentLength = size
    })
    if err != nil {
        return err
    }
    io.Copy(io.Discard, rs.Body)
    rs.Body.Close()
    if rs.StatusCode != http.StatusCreated && rs.StatusCode != http.StatusNoContent && rs.StatusCode != http.StatusOK {
        return NewPathError("PUT", pathpkg.Join(n.UploadURL, n.Folder, name), rs.StatusCode)
    }
    return nil
}

// Assemble moves the .file to the final destination and triggers assembly server-side.
// dest is a WebDAV path relative to the files WebDAV root (e.g., /remote.php/dav/files/<user>/path/to/file)
// You can pass an optional mtime Unix seconds via xOCMtime; pass 0 to skip.
func (n *NextcloudChunkedUpload) Assemble(destAbsoluteURL string, xOCMtime int64) error {
    rs, err := n.c.req("MOVE", n.UploadURL+n.Folder+"/.file", nil, func(rq *http.Request) {
        rq.Header.Add("Destination", destAbsoluteURL)
        if xOCMtime > 0 {
            rq.Header.Add("X-OC-Mtime", strconv.FormatInt(xOCMtime, 10))
        }
    })
    if err != nil {
        return err
    }
    io.Copy(io.Discard, rs.Body)
    rs.Body.Close()
    if rs.StatusCode != http.StatusCreated && rs.StatusCode != http.StatusNoContent && rs.StatusCode != http.StatusOK {
        return NewPathError("MOVE", destAbsoluteURL, rs.StatusCode)
    }
    return nil
}

// Abort deletes the upload folder to abort the upload.
func (n *NextcloudChunkedUpload) Abort() error {
    rs, err := n.c.req("DELETE", n.UploadURL+n.Folder+"/", nil, nil)
    if err != nil {
        return err
    }
    io.Copy(io.Discard, rs.Body)
    rs.Body.Close()
    if rs.StatusCode != http.StatusOK && rs.StatusCode != http.StatusNoContent && rs.StatusCode != http.StatusNotFound {
        return NewPathError("DELETE", n.UploadURL+n.Folder+"/", rs.StatusCode)
    }
    return nil
}

// WriteStreamNextcloudChunked performs a chunked upload to Nextcloud and assembles it to destAbsoluteURL.
// - baseUploadURL: absolute uploads URL: <server>/remote.php/dav/uploads/<user>/
// - destAbsoluteURL: absolute destination URL: <server>/remote.php/dav/files/<user>/path
// - chunkSize: size in bytes for each chunk; last chunk may be smaller.
// The reader r will be consumed sequentially.
func (c *Client) WriteStreamNextcloudChunked(baseUploadURL, destAbsoluteURL string, r io.Reader, chunkSize int64, mtime int64) error {
    nc := &NextcloudChunkedUpload{c: c}
    if err := nc.Start(baseUploadURL); err != nil {
        return err
    }

    var offset int64 = 0
    for {
        // read up to chunkSize into memory buffer
        lr := io.LimitedReader{R: r, N: chunkSize}
    chunkBuf := &bytesBufferPool{}
    if err := chunkBuf.readFrom(&lr); err != nil {
            _ = nc.Abort()
            return err
        }
        if chunkBuf.len == 0 {
            break
        }
        end := offset + chunkBuf.len - 1
    if err := nc.UploadChunk(offset, end, bytes.NewReader(chunkBuf.buf), chunkBuf.len); err != nil {
            _ = nc.Abort()
            return err
        }
        offset = end + 1
        if chunkBuf.buf != nil {
            chunkBuf.release()
        }
    }

    if err := nc.Assemble(destAbsoluteURL, mtime); err != nil {
        _ = nc.Abort()
        return err
    }
    return nil
}

// bytesBufferPool is a tiny helper without external deps
type bytesBufferPool struct {
    buf []byte
    len int64
}

func (b *bytesBufferPool) readFrom(r io.Reader) error {
    const maxChunk = 8 * 1024 * 1024 // 8MB growth steps
    if b.buf == nil {
        b.buf = make([]byte, 0, maxChunk)
    }
    for {
        tmp := make([]byte, 32*1024)
        n, err := r.Read(tmp)
        if n > 0 {
            b.buf = append(b.buf, tmp[:n]...)
            b.len += int64(n)
        }
        if err == io.EOF {
            return nil
        }
        if err != nil {
            return err
        }
    }
}

func (b *bytesBufferPool) release() { b.buf = nil; b.len = 0 }

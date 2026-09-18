#!/usr/bin/env node
'use strict';

/*
 * svndump.js
 *
 * Dependency-free SVN dump reader.
 *
 * Supports:
 *   - SVN dump format 2/3
 *   - revision records
 *   - node records belonging to revisions
 *   - add/change/delete/replace
 *   - Node-copyfrom-path / Node-copyfrom-rev
 *   - regular file contents
 *   - svndiff version 0
 *   - automatic PROJECTNAME/branches and PROJECTNAME/tags discovery
 *   - extraction of a branch/tag at a selected revision
 *
 * No svn, svnadmin or npm packages are required.
 *
 * Usage:
 *
 *   node svndump.js list repository.dump
 *
 *   node svndump.js branches repository.dump
 *
 *   node svndump.js tags repository.dump
 *
 *   node svndump.js extract repository.dump \
 *       PROJECTNAME/branches/mybranch ./output
 *
 *   node svndump.js extract repository.dump \
 *       PROJECTNAME/tags/v1.2.3 ./output
 *
 *   node svndump.js extract repository.dump \
 *       PROJECTNAME/branches/mybranch ./output \
 *       --revision 1234
 *
 *   You can also specify just:
 *
 *       branches/mybranch
 *
 *   if the dump contains a single PROJECTNAME.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const VERSION = '2.0.0';

/* ------------------------------------------------------------------------- */
/* General utilities                                                         */
/* ------------------------------------------------------------------------- */

function die(message) {
    console.error(`Error: ${message}`);
    process.exitCode = 1;
}

function usage() {
    console.log(`
svndump.js ${VERSION}

Read and extract an SVN dump without svn/svnadmin.

Commands:

  list <dump>
      List branches and tags.

  branches <dump>
      List branches.

  tags <dump>
      List tags.

  extract <dump> <repository-path> <output-dir> [options]
      Extract a repository path.

Options:

  --revision <number>
      Extract state as of this SVN revision.
      Default: latest revision.

  --progress
      Print progress while replaying revisions.

  --progress-every <number>
      Print every N revisions.
      Default: 100.

Examples:

  node svndump.js list repo.dump

  node svndump.js branches repo.dump

  node svndump.js tags repo.dump

  node svndump.js extract repo.dump PROJECTNAME/branches/test ./out

  node svndump.js extract repo.dump branches/test ./out

  node svndump.js extract repo.dump PROJECTNAME/tags/1.2.3 ./out

  node svndump.js extract repo.dump branches/test ./out --revision 1500
`);
}

function normalizeRepoPath(p) {
    if (p == null) return '';

    p = String(p)
        .replace(/\\/g, '/')
        .replace(/^\/+/, '');

    p = path.posix.normalize(p);

    if (p === '.') return '';

    if (p === '..') {
        return '';
    }

    while (p.startsWith('../')) {
        p = p.substring(3);
    }

    return p;
}

function parentPath(p) {
    const i = p.lastIndexOf('/');
    return i < 0 ? '' : p.substring(0, i);
}

function baseName(p) {
    const i = p.lastIndexOf('/');
    return i < 0 ? p : p.substring(i + 1);
}

function isDescendantOrSelf(p, root) {
    return p === root || p.startsWith(root + '/');
}

function relativeRepoPath(p, root) {
    if (p === root) return '';
    return p.substring(root.length + 1);
}

function sha256(buffer) {
    return crypto
        .createHash('sha256')
        .update(buffer)
        .digest('hex');
}

function parseInteger(value, name) {
    const n = Number(value);

    if (!Number.isSafeInteger(n) || n < 0) {
        throw new Error(`Invalid ${name}: ${value}`);
    }

    return n;
}

/* ------------------------------------------------------------------------- */
/* Random access reader                                                      */
/* ------------------------------------------------------------------------- */

class RandomReader {
    constructor(filename) {
        this.filename = filename;
        this.fd = null;
        this.size = 0;
    }

    async open() {
        this.fd = await fsp.open(this.filename, 'r');
        this.size = (await this.fd.stat()).size;
    }

    async close() {
        if (this.fd) {
            await this.fd.close();
            this.fd = null;
        }
    }

    async readAt(position, length) {
        if (length === 0) {
            return Buffer.alloc(0);
        }

        if (position < 0 || position + length > this.size) {
            throw new Error(
                `Attempt to read outside dump: offset=${position}, length=${length}`
            );
        }

        const buffer = Buffer.allocUnsafe(length);
        let done = 0;

        while (done < length) {
            const result = await this.fd.read(
                buffer,
                done,
                length - done,
                position + done
            );

            if (result.bytesRead === 0) {
                throw new Error(
                    `Unexpected EOF at offset ${position + done}`
                );
            }

            done += result.bytesRead;
        }

        return buffer;
    }

    async readByte(position) {
        return (await this.readAt(position, 1))[0];
    }

    async readLine(position) {
        const chunks = [];
        let pos = position;

        while (pos < this.size) {
            const b = await this.readByte(pos++);

            if (b === 0x0a) {
                let result = Buffer.concat(chunks)
                    .toString('utf8');

                if (result.endsWith('\r')) {
                    result = result.substring(
                        0,
                        result.length - 1
                    );
                }

                return {
                    text: result,
                    next: pos
                };
            }

            chunks.push(Buffer.from([b]));

            /*
             * SVN headers should be tiny. This catches corrupt dumps
             * without imposing an unnecessarily small limit.
             */
            if (chunks.length > 64 * 1024 * 1024) {
                throw new Error(
                    `Header line exceeds 64 MB at offset ${position}`
                );
            }
        }

        if (chunks.length === 0) {
            return {
                text: null,
                next: pos
            };
        }

        return {
            text: Buffer.concat(chunks).toString('utf8'),
            next: pos
        };
    }
}

/* ------------------------------------------------------------------------- */
/* Header parser                                                             */
/* ------------------------------------------------------------------------- */

/*
 * Reads one SVN dump header block.
 *
 * The block ends at the blank line.
 *
 * Important:
 *
 *     Revision-number: N
 *
 * is a header block in exactly the same sense as:
 *
 *     Node-path: ...
 *
 * We therefore return the headers to the caller instead of assuming
 * anything about what record follows.
 */

async function readHeaders(reader, position) {
    const headers = {};
    let pos = position;

    while (true) {
        const line = await reader.readLine(pos);

        pos = line.next;

        if (line.text === null) {
            return {
                headers,
                next: pos,
                eof: true
            };
        }

        /*
         * Blank line terminates the header block.
         */
        if (line.text === '') {
            return {
                headers,
                next: pos,
                eof: false
            };
        }

        const colon = line.text.indexOf(':');

        if (colon < 0) {
            throw new Error(
                `Malformed header at offset ${pos}: ${line.text}`
            );
        }

        const key = line.text.substring(0, colon);

        let value = line.text.substring(colon + 1);

        if (value.startsWith(' ')) {
            value = value.substring(1);
        }

        headers[key] = value;
    }
}

/* ------------------------------------------------------------------------- */
/* SVN dump content lengths                                                  */
/* ------------------------------------------------------------------------- */

function headerInteger(headers, name, defaultValue = 0) {
    if (headers[name] == null) {
        return defaultValue;
    }

    return parseInteger(
        headers[name],
        name
    );
}

function contentLength(headers) {
    /*
     * Content-length is the authoritative length when present.
     *
     * For robustness, if it is absent, calculate it from the two
     * component lengths.
     */
    if (headers['Content-length'] != null) {
        return headerInteger(
            headers,
            'Content-length'
        );
    }

    return (
        headerInteger(
            headers,
            'Prop-content-length'
        ) +
        headerInteger(
            headers,
            'Text-content-length'
        )
    );
}

/* ------------------------------------------------------------------------- */
/* Blob store                                                                */
/* ------------------------------------------------------------------------- */

class BlobStore {
    constructor(directory) {
        this.directory = directory;
    }

    async init() {
        await fsp.mkdir(
            this.directory,
            { recursive: true }
        );
    }

    async put(buffer) {
        const hash = sha256(buffer);
        const filename = path.join(
            this.directory,
            hash
        );

        try {
            await fsp.access(
                filename,
                fs.constants.F_OK
            );
        } catch {
            await fsp.writeFile(
                filename,
                buffer
            );
        }

        return filename;
    }

    async read(filename) {
        return fsp.readFile(filename);
    }

    async copyTo(filename, destination) {
        await fsp.copyFile(
            filename,
            destination
        );
    }
}

/* ------------------------------------------------------------------------- */
/* File history                                                              */
/* ------------------------------------------------------------------------- */

/*
 * For every repository file path we keep:
 *
 *     revision
 *     blob
 *     deleted
 *
 * The actual contents live in BlobStore, not RAM.
 */

class History {
    constructor() {
        this.files = new Map();
    }

    record(
        repositoryPath,
        revision,
        blob,
        deleted
    ) {
        let list =
            this.files.get(repositoryPath);

        if (!list) {
            list = [];
            this.files.set(
                repositoryPath,
                list
            );
        }

        list.push({
            revision,
            blob,
            deleted
        });
    }

    lookup(repositoryPath, revision) {
        const list =
            this.files.get(repositoryPath);

        if (!list) {
            return null;
        }

        let low = 0;
        let high = list.length - 1;
        let answer = null;

        while (low <= high) {
            const middle =
                (low + high) >> 1;

            const item = list[middle];

            if (item.revision <= revision) {
                answer = item;
                low = middle + 1;
            } else {
                high = middle - 1;
            }
        }

        if (!answer || answer.deleted) {
            return null;
        }

        return answer.blob;
    }

    filesAt(repositoryPath, revision) {
        const result = [];

        for (const [
            p,
            list
        ] of this.files) {
            if (
                !isDescendantOrSelf(
                    p,
                    repositoryPath
                )
            ) {
                continue;
            }

            const blob =
                this.lookup(
                    p,
                    revision
                );

            if (blob) {
                result.push([
                    p,
                    blob
                ]);
            }
        }

        return result;
    }
}

/* ------------------------------------------------------------------------- */
/* Repository state                                                           */
/* ------------------------------------------------------------------------- */

class Repository {
    constructor(blobStore) {
        this.blobStore = blobStore;

        /*
         * Current tree:
         *
         *     path -> { kind:'file', blob }
         *     path -> { kind:'dir' }
         */
        this.nodes = new Map();

        this.files = new Map();
        this.directories = new Set();

        this.history = new History();

        this.nodes.set(
            '',
            { kind: 'dir' }
        );

        this.directories.add('');

        this.revision = -1;
    }

    ensureParentDirectories(p) {
        let parent = parentPath(p);

        while (parent !== '') {
            if (
                !this.directories.has(parent)
            ) {
                this.directories.add(parent);

                this.nodes.set(
                    parent,
                    { kind: 'dir' }
                );
            }

            parent = parentPath(parent);
        }
    }

    async setDirectory(p) {
        p = normalizeRepoPath(p);

        this.ensureParentDirectories(p);

        this.nodes.set(
            p,
            { kind: 'dir' }
        );

        this.directories.add(p);
        this.files.delete(p);
    }

    async setFile(
        p,
        blob,
        revision
    ) {
        p = normalizeRepoPath(p);

        this.ensureParentDirectories(p);

        this.nodes.set(
            p,
            {
                kind: 'file',
                blob
            }
        );

        this.files.set(
            p,
            blob
        );

        this.directories.delete(p);

        this.history.record(
            p,
            revision,
            blob,
            false
        );
    }

    deleteTree(
        root,
        revision
    ) {
        root = normalizeRepoPath(root);

        const removed = [];

        for (const p of this.nodes.keys()) {
            if (
                p === root ||
                isDescendantOrSelf(
                    p,
                    root
                )
            ) {
                removed.push(p);
            }
        }

        for (const p of removed) {
            const node =
                this.nodes.get(p);

            if (
                node &&
                node.kind === 'file'
            ) {
                this.history.record(
                    p,
                    revision,
                    null,
                    true
                );
            }

            this.nodes.delete(p);
            this.files.delete(p);
            this.directories.delete(p);
        }
    }

    async deletePath(
        p,
        revision
    ) {
        this.deleteTree(
            p,
            revision
        );
    }

    async copyPath(
        source,
        sourceRevision,
        destination,
        revision
    ) {
        source =
            normalizeRepoPath(source);

        destination =
            normalizeRepoPath(destination);

        /*
         * Remove existing destination.
         */
        if (
            this.nodes.has(destination)
        ) {
            this.deleteTree(
                destination,
                revision
            );
        }

        /*
         * First see if source is a file.
         */
        const sourceBlob =
            this.history.lookup(
                source,
                sourceRevision
            );

        if (sourceBlob) {
            await this.setFile(
                destination,
                sourceBlob,
                revision
            );

            return;
        }

        /*
         * Otherwise assume it is a directory.
         */
        await this.setDirectory(
            destination
        );

        const copiedFiles =
            this.history.filesAt(
                source,
                sourceRevision
            );

        /*
         * Create all copied files.
         */
        for (const [
            oldPath,
            blob
        ] of copiedFiles) {
            const relative =
                relativeRepoPath(
                    oldPath,
                    source
                );

            const newPath =
                relative
                    ? `${destination}/${relative}`
                    : destination;

            await this.setFile(
                newPath,
                blob,
                revision
            );
        }

        /*
         * Reconstruct directory nodes from file paths.
         */
        const dirs = new Set();

        for (const [
            oldPath
        ] of copiedFiles) {
            let current =
                parentPath(oldPath);

            while (
                current &&
                isDescendantOrSelf(
                    current,
                    source
                )
            ) {
                if (
                    current === source
                ) {
                    break;
                }

                const relative =
                    relativeRepoPath(
                        current,
                        source
                    );

                if (relative) {
                    dirs.add(
                        `${destination}/${relative}`
                    );
                }

                current =
                    parentPath(current);
            }
        }

        for (const dir of dirs) {
            await this.setDirectory(
                dir
            );
        }
    }
}

/* ------------------------------------------------------------------------- */
/* svndiff decoder                                                            */
/* ------------------------------------------------------------------------- */

/*
 * SVN svndiff version 0.
 *
 * Header:
 *
 *     SVN\0
 *     version
 *
 * Each window contains:
 *
 *     source offset
 *     source length
 *     target length
 *     instruction length
 *     new-data length
 *
 * followed by instructions and new data.
 */

function readVarInt(
    buffer,
    state
) {
    let value = 0;
    let count = 0;

    while (
        state.pos <
        buffer.length
    ) {
        const b =
            buffer[state.pos++];

        value =
            value * 128 +
            (b & 0x7f);

        if (
            !Number.isSafeInteger(
                value
            )
        ) {
            throw new Error(
                'svndiff integer exceeds JavaScript safe integer range'
            );
        }

        count++;

        if (
            (b & 0x80) === 0
        ) {
            return value;
        }

        if (count > 10) {
            throw new Error(
                'Invalid svndiff integer'
            );
        }
    }

    throw new Error(
        'Unexpected EOF in svndiff integer'
    );
}

function decodeSvndiff(
    delta,
    source
) {
    if (delta.length < 5) {
        throw new Error(
            'svndiff data is too short'
        );
    }

    if (
        delta[0] !== 0x53 ||
        delta[1] !== 0x56 ||
        delta[2] !== 0x4e ||
        delta[3] !== 0x00
    ) {
        throw new Error(
            'Invalid svndiff header'
        );
    }

    const version = delta[4];

    if (version !== 0) {
        throw new Error(
            `Unsupported svndiff version ${version}; only version 0 is supported`
        );
    }

    let pos = 5;

    const windows = [];

    while (
        pos < delta.length
    ) {
 

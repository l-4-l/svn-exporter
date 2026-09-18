#!/usr/bin/env node
'use strict';

/*
 * svndump.js
 *
 * Dependency-free SVN dump reader/extractor.
 *
 * Usage:
 *
 *   node svndump.js list repo.dump
 *   node svndump.js branches repo.dump
 *   node svndump.js tags repo.dump
 *
 *   node svndump.js extract repo.dump branches/foo ./output
 *   node svndump.js extract repo.dump tags/v1.2.3 ./output
 *
 *   node svndump.js extract repo.dump branches/foo ./output --revision 1234
 *
 * Optional:
 *
 *   --branches-prefix branches
 *   --tags-prefix tags
 *
 * Notes:
 *   - Repository paths are treated as UTF-8.
 *   - SVN dump paths may start with "/"; the utility normalizes them.
 *   - svndiff version 0 is supported.
 *   - Version 1/2 svndiff is rejected with an explanatory error.
 *
 * The program keeps the current repository tree in memory, but file
 * contents are stored in temporary files. Historical file versions are
 * also stored on disk so copyfrom revisions can be reconstructed.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const VERSION = '1.0.0';

function die(message, code = 1) {
    console.error(`Error: ${message}`);
    process.exitCode = code;
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
      Extract the repository path at the latest revision.

Options:

  --revision <number>
      Extract the state as of this SVN revision.

  --branches-prefix <path>
      Branch root. Default: branches

  --tags-prefix <path>
      Tag root. Default: tags

Examples:

  node svndump.js list repo.dump

  node svndump.js branches repo.dump

  node svndump.js tags repo.dump

  node svndump.js extract repo.dump branches/release ./release

  node svndump.js extract repo.dump tags/v1.2.3 ./source

  node svndump.js extract repo.dump branches/release ./source --revision 1527
`);
}

/* ------------------------------------------------------------------------- */
/* Utilities                                                                 */
/* ------------------------------------------------------------------------- */

function normalizeRepoPath(p) {
    if (p == null) return '';

    p = String(p).replace(/\\/g, '/');

    while (p.startsWith('/')) {
        p = p.slice(1);
    }

    p = path.posix.normalize(p);

    if (p === '.') return '';

    while (p.startsWith('../')) {
        p = p.slice(3);
    }

    if (p === '..') return '';

    return p;
}

function parentPath(p) {
    const i = p.lastIndexOf('/');
    return i < 0 ? '' : p.slice(0, i);
}

function baseName(p) {
    const i = p.lastIndexOf('/');
    return i < 0 ? p : p.slice(i + 1);
}

function isDescendantOrSelf(p, root) {
    return p === root || p.startsWith(root + '/');
}

function relativeRepoPath(p, root) {
    if (p === root) return '';
    return p.slice(root.length + 1);
}

function mkdirpSync(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

async function mkdirp(dir) {
    await fsp.mkdir(dir, { recursive: true });
}

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function parseInteger(value, field) {
    const n = Number(value);
    if (!Number.isSafeInteger(n) || n < 0) {
        throw new Error(`Invalid ${field}: ${value}`);
    }
    return n;
}

/* ------------------------------------------------------------------------- */
/* Random-access file reader                                                  */
/* ------------------------------------------------------------------------- */

class RandomReader {
    constructor(filename) {
        this.filename = filename;
        this.fd = null;
        this.size = 0;
    }

    async open() {
        this.fd = await fsp.open(this.filename, 'r');
        const st = await this.fd.stat();
        this.size = st.size;
    }

    async close() {
        if (this.fd) {
            await this.fd.close();
            this.fd = null;
        }
    }

    async readAt(position, length) {
        if (length === 0) return Buffer.alloc(0);

        const buffer = Buffer.allocUnsafe(length);
        let done = 0;

        while (done < length) {
            const { bytesRead } = await this.fd.read(
                buffer,
                done,
                length - done,
                position + done
            );

            if (bytesRead === 0) {
                throw new Error(
                    `Unexpected EOF at offset ${position + done}`
                );
            }

            done += bytesRead;
        }

        return buffer;
    }

    async readByte(position) {
        const b = await this.readAt(position, 1);
        return b[0];
    }

    async readLine(position) {
        const chunks = [];
        let pos = position;

        // Header lines are normally short. We nevertheless impose a
        // generous sanity limit to detect corrupted dumps.
        const MAX_LINE = 16 * 1024 * 1024;

        while (pos < this.size) {
            const b = await this.readByte(pos);
            pos++;

            if (b === 0x0a) {
                const data = Buffer.concat(chunks).toString('utf8');
                return {
                    text: data.endsWith('\r')
                        ? data.slice(0, -1)
                        : data,
                    next: pos
                };
            }

            chunks.push(Buffer.from([b]));

            if (pos - position > MAX_LINE) {
                throw new Error(`Header line exceeds ${MAX_LINE} bytes`);
            }
        }

        if (chunks.length === 0) {
            return { text: null, next: pos };
        }

        return {
            text: Buffer.concat(chunks).toString('utf8'),
            next: pos
        };
    }
}

/* ------------------------------------------------------------------------- */
/* Dump headers                                                               */
/* ------------------------------------------------------------------------- */

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
                `Malformed dump header at offset ${pos}: ${JSON.stringify(line.text)}`
            );
        }

        const key = line.text.slice(0, colon);
        let value = line.text.slice(colon + 1);

        if (value.startsWith(' ')) {
            value = value.slice(1);
        }

        headers[key] = value;
    }
}

/* ------------------------------------------------------------------------- */
/* SVN property parser                                                        */
/* ------------------------------------------------------------------------- */

/*
 * SVN dump property blocks use:
 *
 *   K <length>\n
 *   <key bytes>
 *   V <length>\n
 *   <value bytes>
 *   ...
 *   PROPS-END\n
 *
 * We don't actually need most properties for extraction, but parsing them
 * allows us to locate the file text correctly.
 */

function parseProperties(buffer) {
    const props = {};
    let pos = 0;

    function readLine() {
        const nl = buffer.indexOf(0x0a, pos);

        if (nl < 0) {
            throw new Error('Malformed SVN property block: missing newline');
        }

        const line = buffer.subarray(pos, nl).toString('utf8');
        pos = nl + 1;

        return line.endsWith('\r') ? line.slice(0, -1) : line;
    }

    while (pos < buffer.length) {
        const line = readLine();

        if (line === 'PROPS-END') {
            return props;
        }

        if (!line.startsWith('K ')) {
            throw new Error(`Malformed property block: ${line}`);
        }

        const keyLength = Number(line.slice(2));

        if (!Number.isSafeInteger(keyLength) || keyLength < 0) {
            throw new Error(`Invalid property key length: ${keyLength}`);
        }

        if (pos + keyLength > buffer.length) {
            throw new Error('Property key exceeds property block');
        }

        const key = buffer.subarray(pos, pos + keyLength).toString('utf8');
        pos += keyLength;

        // Key and value are followed by a newline.
        if (buffer[pos] !== 0x0a) {
            throw new Error('Malformed property block after key');
        }
        pos++;

        const valueLine = readLine();

        if (!valueLine.startsWith('V ')) {
            throw new Error(`Malformed property value header: ${valueLine}`);
        }

        const valueLength = Number(valueLine.slice(2));

        if (!Number.isSafeInteger(valueLength) || valueLength < 0) {
            throw new Error(`Invalid property value length: ${valueLength}`);
        }

        if (pos + valueLength > buffer.length) {
            throw new Error('Property value exceeds property block');
        }

        const value = Buffer.from(buffer.subarray(pos, pos + valueLength));
        pos += valueLength;

        if (buffer[pos] !== 0x0a) {
            throw new Error('Malformed property block after value');
        }
        pos++;

        props[key] = value;
    }

    throw new Error('Malformed SVN property block: PROPS-END missing');
}

/* ------------------------------------------------------------------------- */
/* svndiff                                                                     */
/* ------------------------------------------------------------------------- */

/*
 * SVN's svndiff format is based on windows.
 *
 * Window:
 *
 *   source offset     varint
 *   source length     varint
 *   target length     varint
 *   instruction len   varint
 *   new data len      varint
 *   instructions
 *   new data
 *
 * Instruction:
 *
 *   top 2 bits:
 *      00 = copy from source
 *      01 = copy from target
 *      10 = insert new data
 *
 *   low 6 bits:
 *      length, or 0 followed by varint(length)
 *
 * For normal SVN dumps, svndiff version 0 is commonly encountered.
 */

function readVarInt(buffer, state) {
    let value = 0;
    let count = 0;

    while (state.pos < buffer.length) {
        const b = buffer[state.pos++];

        value = value * 128 + (b & 0x7f);
        count++;

        if (!Number.isSafeInteger(value)) {
            throw new Error('svndiff integer exceeds JavaScript safe integer range');
        }

        if ((b & 0x80) === 0) {
            return value;
        }

        if (count > 10) {
            throw new Error('Invalid svndiff variable-length integer');
        }
    }

    throw new Error('Unexpected EOF in svndiff integer');
}

function decodeSvndiff(delta, source) {
    if (delta.length < 4) {
        throw new Error('svndiff data is too short');
    }

    if (
        delta[0] !== 0x53 || // S
        delta[1] !== 0x56 || // V
        delta[2] !== 0x4e || // N
        delta[3] !== 0x00
    ) {
        throw new Error('Invalid svndiff header');
    }

    // svndiff version byte after "SVN\0".
    const version = delta[4];

    if (version !== 0) {
        throw new Error(
            `Unsupported svndiff version ${version}; this utility currently supports svndiff version 0`
        );
    }

    let pos = 5;
    let previousTarget = Buffer.alloc(0);
    const windows = [];

    while (pos < delta.length) {
        const state = { pos };

        const sourceOffset = readVarInt(delta, state);
        const sourceLength = readVarInt(delta, state);
        const targetLength = readVarInt(delta, state);
        const instructionLength = readVarInt(delta, state);
        const newDataLength = readVarInt(delta, state);

        pos = state.pos;

        if (sourceOffset + sourceLength > source.length) {
            throw new Error(
                `svndiff source window exceeds source: offset=${sourceOffset}, length=${sourceLength}, source=${source.length}`
            );
        }

        if (pos + instructionLength + newDataLength > delta.length) {
            throw new Error('svndiff window exceeds delta buffer');
        }

        const instructions = delta.subarray(
            pos,
            pos + instructionLength
        );

        pos += instructionLength;

        const newData = delta.subarray(
            pos,
            pos + newDataLength
        );

        pos += newDataLength;

        const sourceWindow = source.subarray(
            sourceOffset,
            sourceOffset + sourceLength
        );

        const output = Buffer.allocUnsafe(targetLength);

        let ip = 0;
        let np = 0;
        let op = 0;

        while (ip < instructions.length) {
            const opcode = instructions[ip++];

            let length = opcode & 0x3f;

            if (length === 0) {
                const st = { pos: ip };
                length = readVarInt(instructions, st);
                ip = st.pos;
            }

            if (length < 0 || !Number.isSafeInteger(length)) {
                throw new Error('Invalid svndiff instruction length');
            }

            const type = opcode >> 6;

            if (type === 0) {
                // Copy from source window.
                let offset;

                if (opcode & 0x20) {
                    const st = { pos: ip };
                    offset = readVarInt(instructions, st);
                    ip = st.pos;
                } else {
                    if (ip + 1 > instructions.length) {
                        throw new Error('Truncated svndiff source offset');
                    }

                    offset = instructions[ip++];
                }

                if (offset + length > sourceWindow.length) {
                    throw new Error(
                        `svndiff source copy exceeds window: offset=${offset}, length=${length}, window=${sourceWindow.length}`
                    );
                }

                if (op + length > output.length) {
                    throw new Error('svndiff target overflow');
                }

                sourceWindow.copy(output, op, offset, offset + length);
                op += length;
            } else if (type === 1) {
                // Copy from target window already produced.
                let offset;

                if (opcode & 0x20) {
                    const st = { pos: ip };
                    offset = readVarInt(instructions, st);
                    ip = st.pos;
                } else {
                    if (ip + 1 > instructions.length) {
                        throw new Error('Truncated svndiff target offset');
                    }

                    offset = instructions[ip++];
                }

                if (offset >= op && length > 0) {
                    throw new Error(
                        `Invalid svndiff target copy: offset=${offset}, produced=${op}`
                    );
                }

                if (op + length > output.length) {
                    throw new Error('svndiff target overflow');
                }

                /*
                 * Target copies can overlap. This is intentional and is
                 * equivalent to memmove-style repeated copying.
                 */
                for (let i = 0; i < length; i++) {
                    if (offset + i >= op) {
                        // The newly copied byte can itself be copied again.
                        output[op + i] = output[offset + i];
                    } else {
                        output[op + i] = output[offset + i];
                    }
                }

                op += length;
            } else if (type === 2) {
                // Insert literal bytes from new-data section.
                if (np + length > newData.length) {
                    throw new Error('svndiff new-data overflow');
                }

                if (op + length > output.length) {
                    throw new Error('svndiff target overflow');
                }

                newData.copy(output, op, np, np + length);

                np += length;
                op += length;
            } else {
                throw new Error('Invalid svndiff instruction type');
            }
        }

        if (op !== targetLength) {
            throw new Error(
                `svndiff target length mismatch: expected ${targetLength}, produced ${op}`
            );
        }

        if (np !== newData.length) {
            throw new Error(
                `svndiff new-data mismatch: expected ${newData.length}, consumed ${np}`
            );
        }

        windows.push(output);
        previousTarget = Buffer.concat([previousTarget, output]);
    }

    return Buffer.concat(windows);
}

/* ------------------------------------------------------------------------- */
/* Blob store                                                                  */
/* ------------------------------------------------------------------------- */

class BlobStore {
    constructor(directory) {
        this.directory = directory;
        this.cache = new Map();
    }

    async init() {
        await mkdirp(this.directory);
    }

    async put(buffer) {
        const hash = sha256(buffer);
        const filename = path.join(this.directory, hash);

        try {
            await fsp.access(filename, fs.constants.F_OK);
        } catch {
            await fsp.writeFile(filename, buffer);
        }

        return filename;
    }

    async read(filename) {
        return fsp.readFile(filename);
    }

    async copyTo(filename, destination) {
        await fsp.copyFile(filename, destination);
    }
}

/* ------------------------------------------------------------------------- */
/* Historical file state                                                       */
/* ------------------------------------------------------------------------- */

/*
 * Each path gets a list of versions:
 *
 *   {
 *      revision,
 *      blob,
 *      deleted
 *   }
 *
 * A lookup(path, revision) selects the last version <= revision.
 *
 * This makes copyfrom@revision possible without keeping all file contents
 * in RAM.
 */

class History {
    constructor() {
        this.files = new Map();
    }

    record(pathName, revision, blob, deleted = false) {
        let list = this.files.get(pathName);

        if (!list) {
            list = [];
            this.files.set(pathName, list);
        }

        list.push({
            revision,
            blob,
            deleted
        });
    }

    lookup(pathName, revision) {
        const list = this.files.get(pathName);

        if (!list) return null;

        let lo = 0;
        let hi = list.length - 1;
        let answer = null;

        while (lo <= hi) {
            const mid = (lo + hi) >> 1;
            const item = list[mid];

            if (item.revision <= revision) {
                answer = item;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }

        if (!answer || answer.deleted) return null;

        return answer.blob;
    }

    /*
     * Return all files below root that existed at revision.
     *
     * This is intentionally straightforward rather than highly optimized.
     * For typical SVN branch/tag dumps it is adequate.
     */
    filesAt(root, revision) {
        const result = [];

        for (const [p, list] of this.files) {
            if (!isDescendantOrSelf(p, root) || p === root) {
                continue;
            }

            const blob = this.lookup(p, revision);

            if (blob) {
                result.push([p, blob]);
            }
        }

        return result;
    }
}

/* ------------------------------------------------------------------------- */
/* Repository tree                                                            */
/* ------------------------------------------------------------------------- */

class Repository {
    constructor(blobStore) {
        this.blobStore = blobStore;

        // path -> { kind: 'file', blob } or { kind: 'dir' }
        this.nodes = new Map();

        // Current files only.
        this.files = new Map();

        // Current directories.
        this.directories = new Set();

        this.history = new History();

        this.revision = -1;

        // Records newly observed branch/tag paths.
        this.branches = new Set();
        this.tags = new Set();

        this.nodes.set('', { kind: 'dir' });
        this.directories.add('');
    }

    ensureParentDirectories(p) {
        let parent = parentPath(p);

        while (parent !== '') {
            if (!this.directories.has(parent)) {
                this.directories.add(parent);
                this.nodes.set(parent, { kind: 'dir' });
            }

            parent = parentPath(parent);
        }
    }

    removeTree(root, revision) {
        const toRemove = [];

        for (const p of this.nodes.keys()) {
            if (p === root || isDescendantOrSelf(p, root)) {
                toRemove.push(p);
            }
        }

        for (const p of toRemove) {
            const node = this.nodes.get(p);

            if (node && node.kind === 'file') {
                this.history.record(p, revision, null, true);
            }

            this.nodes.delete(p);
            this.files.delete(p);
            this.directories.delete(p);
        }
    }

    async setDirectory(p) {
        p = normalizeRepoPath(p);

        this.ensureParentDirectories(p);

        this.nodes.set(p, { kind: 'dir' });
        this.directories.add(p);
        this.files.delete(p);
    }

    async setFile(p, blob, revision) {
        p = normalizeRepoPath(p);

        this.ensureParentDirectories(p);

        this.nodes.set(p, {
            kind: 'file',
            blob
        });

        this.files.set(p, blob);
        this.directories.delete(p);

        this.history.record(p, revision, blob, false);
    }

    async deletePath(p, revision) {
        p = normalizeRepoPath(p);

        this.removeTree(p, revision);
    }

    async copyPath(source, sourceRevision, destination, revision) {
        source = normalizeRepoPath(source);
        destination = normalizeRepoPath(destination);

        /*
         * Remove destination first if it exists.
         */
        if (
            this.nodes.has(destination) ||
            this.directories.has(destination)
        ) {
            this.removeTree(destination, revision);
        }

        /*
         * Source can be a file.
         */
        const sourceFile = this.history.lookup(source, sourceRevision);

        if (sourceFile) {
            await this.setFile(destination, sourceFile, revision);
            return;
        }

        /*
         * Source can be a directory.
         *
         * The historical file index is sufficient for reconstructing
         * directory copies.
         */
        const copiedFiles = this.history.filesAt(
            source,
            sourceRevision
        );

        await this.setDirectory(destination);

        for (const [oldPath, blob] of copiedFiles) {
            const relative = relativeRepoPath(oldPath, source);
            const newPath = relative
                ? `${destination}/${relative}`
                : destination;

            await this.setFile(newPath, blob, revision);
        }

        /*
         * Reconstruct directories as well. Directories themselves don't
         * need historical content, so derive them from copied files.
         */
        const dirs = new Set();

        for (const [oldPath] of copiedFiles) {
            let d = parentPath(oldPath);

            while (
                d &&
                isDescendantOrSelf(d, source)
            ) {
                const relative = relativeRepoPath(d, source);

                if (relative) {
                    dirs.add(`${destination}/${relative}`);
                }

                if (d === source) break;

                d = parentPath(d);
            }
        }

        for (const d of dirs) {
            await this.setDirectory(d);
        }
    }

    discoverBranchTag(pathName) {
        const parts = pathName.split('/');

        if (parts.length < 2) return;

        if (parts[0] === 'branches') {
            this.branches.add(parts.slice(0, 2).join('/'));
        }

        if (parts[0] === 'tags') {
            this.tags.add(parts.slice(0, 2).join('/'));
        }
    }
}

/* ------------------------------------------------------------------------- */
/* SVN dump processing                                                         */
/* ------------------------------------------------------------------------- */

async function readContent(reader, position, length) {
    if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error(`Invalid content length: ${length}`);
    }

    return reader.readAt(position, length);
}

function getContentLength(headers) {
    if (headers['Content-length'] != null) {
        return parseInteger(
            headers['Content-length'],
            'Content-length'
        );
    }

    const prop = headers['Prop-content-length']
        ? parseInteger(
              headers['Prop-content-length'],
              'Prop-content-length'
          )
        : 0;

    const text = headers['Text-content-length']
        ? parseInteger(
              headers['Text-content-length'],
              'Text-content-length'
          )
        : 0;

    return prop + text;
}

function contentPositionAfterHeaders(position, headers) {
    /*
     * position already points immediately after the blank line.
     */
    return position;
}

async function processRevision(
    reader,
    repository,
    revision,
    revisionHeaders,
    revisionContentStart,
    revisionContentLength,
    options
) {
    const revisionEnd =
        revisionContentStart + revisionContentLength;

    let pos = revisionContentStart;

    /*
     * Revision properties occupy the first Prop-content-length bytes.
     */
    const revisionPropLength = revisionHeaders[
        'Prop-content-length'
    ]
        ? parseInteger(
              revisionHeaders['Prop-content-length'],
              'Prop-content-length'
          )
        : 0;

    if (revisionPropLength > 0) {
        await readContent(
            reader,
            pos,
            revisionPropLength
        );

        pos += revisionPropLength;
    }

    /*
     * The rest consists of node records.
     */
    while (pos < revisionEnd) {
        const nodeHeadersResult = await readHeaders(reader, pos);

        if (nodeHeadersResult.eof) {
            break;
        }

        pos = nodeHeadersResult.next;

        const h = nodeHeadersResult.headers;

        if (!h['Node-path']) {
            throw new Error(
                `Revision ${revision}: node record has no Node-path`
            );
        }

        const nodePath = normalizeRepoPath(h['Node-path']);

        const nodeContentLength = getContentLength(h);

        if (pos + nodeContentLength > revisionEnd) {
            throw new Error(
                `Revision ${revision}: node content exceeds revision boundary`
            );
        }

        const propLength = h['Prop-content-length']
            ? parseInteger(
                  h['Prop-content-length'],
                  'Prop-content-length'
              )
            : 0;

        const textLength = h['Text-content-length']
            ? parseInteger(
                  h['Text-content-length'],
                  'Text-content-length'
              )
            : 0;

        const content = nodeContentLength
            ? await readContent(
                  reader,
                  pos,
                  nodeContentLength
              )
            : Buffer.alloc(0);

        pos += nodeContentLength;

        /*
         * There can be padding/newline between records depending on the
         * dump writer. Normally Content-length covers exactly the content
         * and the next header starts immediately after it.
         */

        const action = h['Node-action'] || 'change';
        const kind = h['Node-kind'];

        const copyFromPath = h['Node-copyfrom-path']
            ? normalizeRepoPath(h['Node-copyfrom-path'])
            : null;

        const copyFromRevision = h['Node-copyfrom-rev'] != null
            ? parseInteger(
                  h['Node-copyfrom-rev'],
                  'Node-copyfrom-rev'
              )
            : null;

        repository.discoverBranchTag(nodePath);

        /*
         * For a copy/add operation, reconstruct the copied source first.
         */
        if (
            (action === 'add' || action === 'replace') &&
            copyFromPath != null &&
            copyFromRevision != null
        ) {
            if (action === 'replace') {
                await repository.deletePath(
                    nodePath,
                    revision
                );
            }

            await repository.copyPath(
                copyFromPath,
                copyFromRevision,
                nodePath,
                revision
            );
        } else if (action === 'replace') {
            await repository.deletePath(
                nodePath,
                revision
            );
        } else if (action === 'delete') {
            await repository.deletePath(
                nodePath,
                revision
            );
            continue;
        } else if (action === 'add') {
            if (kind === 'dir') {
                await repository.setDirectory(nodePath);
            }
        }

        /*
         * If this is a directory, there is normally no file text.
         */
        if (kind === 'dir') {
            if (action !== 'delete') {
                await repository.setDirectory(nodePath);
            }

            continue;
        }

        /*
         * If kind is absent on a change, infer it from the current tree.
         */
        let effectiveKind = kind;

        if (!effectiveKind) {
            const existing = repository.nodes.get(nodePath);

            if (existing) {
                effectiveKind = existing.kind;
            }
        }

        if (effectiveKind !== 'file') {
            continue;
        }

        if (textLength === 0) {
            /*
             * A file property-only change has no text content.
             */
            continue;
        }

        if (propLength > content.length) {
            throw new Error(
                `Revision ${revision}: property length exceeds node content`
            );
        }

        /*
         * Text normally begins immediately after the property block.
         */
        let textStart = propLength;

        /*
         * Some dump producers include a newline separator after the
         * property block. parseProperties consumes its own final newline,
         * so the byte layout remains exactly propLength + textLength.
         */
        const text = content.subarray(
            textStart,
            textStart + textLength
        );

        let fileData;

        if (h['Text-delta'] === 'true') {
            const existing = repository.nodes.get(nodePath);

            if (
                !existing ||
                existing.kind !== 'file' ||
                !existing.blob
            ) {
                throw new Error(
                    `Revision ${revision}: cannot apply text delta to ${nodePath}; no previous file version`
                );
            }

            const source = await repository.blobStore.read(
                existing.blob
            );

            fileData = decodeSvndiff(text, source);
        } else {
            fileData = Buffer.from(text);
        }

        const blob = await repository.blobStore.put(
            fileData
        );

        await repository.setFile(
            nodePath,
            blob,
            revision
        );
    }

    if (pos > revisionEnd) {
        throw new Error(
            `Revision ${revision}: parser passed revision boundary`
        );
    }

    repository.revision = revision;

    if (
        options.progress &&
        revision % options.progressEvery === 0
    ) {
        console.error(
            `Processed revision ${revision}`
        );
    }
}

/* ------------------------------------------------------------------------- */
/* Dump replay                                                                */
/* ------------------------------------------------------------------------- */

async function replayDump(filename, options = {}) {
    const reader = new RandomReader(filename);

    await reader.open();

    const tempRoot = await fsp.mkdtemp(
        path.join(
            os.tmpdir(),
            'svndump-'
        )
    );

    const blobs = new BlobStore(
        path.join(tempRoot, 'blobs')
    );

    await blobs.init();

    const repo = new Repository(blobs);

    let pos = 0;
    let currentRevision = -1;

    try {
        /*
         * SVN dump header.
         *
         * Typical:
         *
         *   SVN-fs-dump-format-version: 2
         *
         *   UUID: ...
         *
         *   ...
         */
        const first = await readHeaders(
            reader,
            pos
        );

        if (first.eof) {
            throw new Error('Empty dump file');
        }

        pos = first.next;

        if (
            first.headers['SVN-fs-dump-format-version'] == null
        ) {
            /*
             * Some streams can have an initial UUID block. If it isn't a
             * recognized dump header, continue treating it as the stream
             * header rather than immediately failing.
             */
        }

        while (pos < reader.size) {
            const result = await readHeaders(
                reader,
                pos
            );

            if (result.eof) break;

            pos = result.next;

            const headers = result.headers;

            if (
                headers['Revision-number'] == null
            ) {
                /*
                 * A UUID/header block can occur before revisions.
                 *
                 * If this record has content, skip it.
                 */
                const length = getContentLength(headers);

                if (length > 0) {
                    pos += length;
                }

                continue;
            }

            currentRevision = parseInteger(
                headers['Revision-number'],
                'Revision-number'
            );

            const contentLength = getContentLength(
                headers
            );

            if (
                pos + contentLength > reader.size
            ) {
                throw new Error(
                    `Revision ${currentRevision} exceeds dump file`
                );
            }

            /*
             * Do not process revisions after requested revision.
             */
            if (
                options.revision != null &&
                currentRevision > options.revision
            ) {
                break;
            }

            await processRevision(
                reader,
                repo,
                currentRevision,
                headers,
                pos,
                contentLength,
                options
            );

            pos += contentLength;
        }

        return {
            repo,
            tempRoot,
            revision: repo.revision
        };
    } catch (error) {
        await reader.close();

        /*
         * Keep temp data only while replay succeeds. On error, remove it.
         */
        await fsp.rm(tempRoot, {
            recursive: true,
            force: true
        }).catch(() => {});

        throw error;
    } finally {
        await reader.close();
    }
}

/* ------------------------------------------------------------------------- */
/* Branch/tag discovery                                                       */
/* ------------------------------------------------------------------------- */

function directChildrenUnder(root, paths) {
    const result = new Set();

    root = normalizeRepoPath(root);

    for (const p of paths) {
        if (!isDescendantOrSelf(p, root) || p === root) {
            continue;
        }

        const relative = relativeRepoPath(p, root);
        const slash = relative.indexOf('/');

        const child =
            slash < 0
                ? relative
                : relative.slice(0, slash);

        if (child) {
            result.add(
                root ? `${root}/${child}` : child
            );
        }
    }

    return [...result].sort(
        (a, b) =>
            a.localeCompare(b, undefined, {
                numeric: true
            })
    );
}

function listBranches(repo, prefix) {
    return directChildrenUnder(
        prefix,
        [...repo.nodes.keys()]
    ).filter(p => {
        const node = repo.nodes.get(p);
        return node && node.kind === 'dir';
    });
}

function listTags(repo, prefix) {
    return directChildrenUnder(
        prefix,
        [...repo.nodes.keys()]
    ).filter(p => {
        const node = repo.nodes.get(p);
        return node && node.kind === 'dir';
    });
}

/* ------------------------------------------------------------------------- */
/* Extraction                                                                 */
/* ------------------------------------------------------------------------- */

async function extractRepositoryPath(
    repo,
    repositoryPath,
    outputDir
) {
    repositoryPath = normalizeRepoPath(
        repositoryPath
    );

    /*
     * Prevent accidental extraction of repository root into an existing
     * directory with surprising semantics.
     */
    if (!repositoryPath) {
        await mkdirp(outputDir);

        for (const [p, node] of repo.nodes) {
            if (p === '') continue;

            const rel = p;

            if (node.kind === 'dir') {
                await mkdirp(
                    path.join(outputDir, ...rel.split('/'))
                );
            }
        }

        for (const [p, blob] of repo.files) {
            const destination = safeOutputPath(
                outputDir,
                p
            );

            await mkdirp(
                path.dirname(destination)
            );

            await repo.blobStore.copyTo(
                blob,
                destination
            );
        }

        return;
    }

    const rootNode = repo.nodes.get(
        repositoryPath
    );

    if (!rootNode) {
        throw new Error(
            `Path does not exist at selected revision: ${repositoryPath}`
        );
    }

    await mkdirp(outputDir);

    if (rootNode.kind === 'file') {
        const destination = path.join(
            outputDir,
            baseName(repositoryPath)
        );

        await repo.blobStore.copyTo(
            rootNode.blob,
            destination
        );

        return;
    }

    /*
     * Directory.
     */
    for (const [p, node] of repo.nodes) {
        if (
            p !== repositoryPath &&
            !isDescendantOrSelf(
                p,
                repositoryPath
            )
        ) {
            continue;
        }

        const relative =
            p === repositoryPath
                ? ''
                : relativeRepoPath(
                      p,
                      repositoryPath
                  );

        if (!relative) continue;

        const destination = safeOutputPath(
            outputDir,
            relative
        );

        if (node.kind === 'dir') {
            await mkdirp(destination);
        }
    }

    for (const [p, blob] of repo.files) {
        if (
            !isDescendantOrSelf(
                p,
                repositoryPath
            )
        ) {
            continue;
        }

        const relative =
            relativeRepoPath(
                p,
                repositoryPath
            );

        if (!relative) continue;

        const destination = safeOutputPath(
            outputDir,
            relative
        );

        await mkdirp(
            path.dirname(destination)
        );

        await repo.blobStore.copyTo(
            blob,
            destination
        );
    }
}

function safeOutputPath(root, relativeRepo) {
    const pieces = relativeRepo
        .split('/')
        .filter(Boolean);

    for (const piece of pieces) {
        if (
            piece === '.' ||
            piece === '..' ||
            piece.includes('\0')
        ) {
            throw new Error(
                `Unsafe repository path: ${relativeRepo}`
            );
        }
    }

    const result = path.resolve(
        root,
        ...pieces
    );

    const resolvedRoot =
        path.resolve(root);

    if (
        result !== resolvedRoot &&
        !result.startsWith(
            resolvedRoot + path.sep
        )
    ) {
        throw new Error(
            `Unsafe extraction path: ${relativeRepo}`
        );
    }

    return result;
}

/* ------------------------------------------------------------------------- */
/* Command implementations                                                    */
/* ------------------------------------------------------------------------- */

async function commandList(
    dump,
    options
) {
    console.error(
        `Reading ${dump}...`
    );

    const result = await replayDump(
        dump,
        options
    );

    const repo = result.repo;

    const branches = listBranches(
        repo,
        options.branchesPrefix
    );

    const tags = listTags(
        repo,
        options.tagsPrefix
    );

    console.log(
        `Revision: ${result.revision}`
    );

    console.log('');
    console.log('Branches:');

    if (branches.length === 0) {
        console.log('  (none)');
    } else {
        for (const b of branches) {
            console.log(`  ${b}`);
        }
    }

    console.log('');
    console.log('Tags:');

    if (tags.length === 0) {
        console.log('  (none)');
    } else {
        for (const t of tags) {
            console.log(`  ${t}`);
        }
    }

    await fsp.rm(
        result.tempRoot,
        {
            recursive: true,
            force: true
        }
    ).catch(() => {});
}

async function commandExtract(
    dump,
    repositoryPath,
    output,
    options
) {
    console.error(
        `Reading ${dump}...`
    );

    const result = await replayDump(
        dump,
        options
    );

    console.error(
        `Repository state reconstructed at revision ${result.revision}`
    );

    console.error(
        `Extracting ${normalizeRepoPath(repositoryPath)}`
    );

    await extractRepositoryPath(
        result.repo,
        repositoryPath,
        output
    );

    console.error(
        `Extracted to ${path.resolve(output)}`
    );

    await fsp.rm(
        result.tempRoot,
        {
            recursive: true,
            force: true
        }
    ).catch(() => {});
}

/* ------------------------------------------------------------------------- */
/* CLI parser                                                                 */
/* ------------------------------------------------------------------------- */

function parseArgs(argv) {
    if (argv.length === 0) {
        usage();
        process.exitCode = 1;
        return null;
    }

    const command = argv[0];

    const options = {
        revision: null,
        branchesPrefix: 'branches',
        tagsPrefix: 'tags',
        progress: false,
        progressEvery: 100
    };

    const positional = [];

    for (let i = 1; i < argv.length; i++) {
        const arg = argv[i];

        if (arg === '--revision') {
            if (i + 1 >= argv.length) {
                throw new Error(
                    '--revision requires a number'
                );
            }

            options.revision = parseInteger(
                argv[++i],
                'revision'
            );
        } else if (arg === '--branches-prefix') {
            if (i + 1 >= argv.length) {
                throw new Error(
                    '--branches-prefix requires a path'
                );
            }

            options.branchesPrefix =
                normalizeRepoPath(
                    argv[++i]
                );
        } else if (arg === '--tags-prefix') {
            if (i + 1 >= argv.length) {
                throw new Error(
                    '--tags-prefix requires a path'
                );
            }

            options.tagsPrefix =
                normalizeRepoPath(
                    argv[++i]
                );
        } else if (arg === '--progress') {
            options.progress = true;
        } else if (arg === '--progress-every') {
            if (i + 1 >= argv.length) {
                throw new Error(
                    '--progress-every requires a number'
                );
            }

            options.progressEvery =
                parseInteger(
                    argv[++i],
                    'progress-every'
                ) || 1;
        } else if (arg === '--help' || arg === '-h') {
            usage();
            return null;
        } else {
            positional.push(arg);
        }
    }

    return {
        command,
        positional,
        options
    };
}

/* ------------------------------------------------------------------------- */
/* Main                                                                       */
/* ------------------------------------------------------------------------- */

async function main() {
    const parsed = parseArgs(
        process.argv.slice(2)
    );

    if (!parsed) return;

    const {
        command,
        positional,
        options
    } = parsed;

    if (command === 'list') {
        if (positional.length !== 1) {
            usage();
            throw new Error(
                'list requires <dump>'
            );
        }

        await commandList(
            positional[0],
            options
        );

        return;
    }

    if (
        command === 'branches' ||
        command === 'tags'
    ) {
        if (positional.length !== 1) {
            usage();
            throw new Error(
                `${command} requires <dump>`
            );
        }

        const result = await replayDump(
            positional[0],
            options
        );

        const list =
            command === 'branches'
                ? listBranches(
                      result.repo,
                      options.branchesPrefix
                  )
                : listTags(
                      result.repo,
                      options.tagsPrefix
                  );

        for (const item of list) {
            console.log(item);
        }

        await fsp.rm(
            result.tempRoot,
            {
                recursive: true,
                force: true
            }
        ).catch(() => {});

        return;
    }

    if (command === 'extract') {
        if (positional.length !== 3) {
            usage();
            throw new Error(
                'extract requires <dump> <repository-path> <output-dir>'
            );
        }

        await commandExtract(
            positional[0],
            positional[1],
            positional[2],
            options
        );

        return;
    }

    usage();

    throw new Error(
        `Unknown command: ${command}`
    );
}

main().catch(error => {
    die(
        error && error.stack
            ? error.stack
            : String(error)
    );
});

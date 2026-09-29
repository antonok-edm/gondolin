'use strict';

// GONDOLIN_VENDORED_NODE_VFS_PATCH: userland compatibility shim
const {
  primordials,
  internalBinding,
  patchRequire,
} = require('../gondolin-shim');
require = patchRequire(require);

const {
  Promise,
  StringPrototypeStartsWith,
} = primordials;

const fs = require('fs');
const os = require('os');
const path = require('path');
const { VirtualProvider } = require('internal/vfs/provider');
const { VirtualFileHandle } = require('internal/vfs/file_handle');
const {
  codes: {
    ERR_INVALID_ARG_VALUE,
  },
} = require('internal/errors');

const { errno: ERRNO } = os.constants;

// XXX(patch): Custom code/changes added for Gondolin
// Permission bits plus sticky; setuid/setgid are never applied to host files.
const kChmodAllowedBits = 0o1777;

// XXX(patch): Custom code/changes added for Gondolin
// This vendored provider intentionally carries local security/compat extensions
// (symlink-escape hardening, hard-link support wiring, and statfs support)

/**
 * A file handle that wraps a real file descriptor.
 */
class RealFileHandle extends VirtualFileHandle {
  #fd;
  #realPath;

  /**
   * @param {string} path The VFS path
   * @param {string} flags The open flags
   * @param {number} mode The file mode
   * @param {number} fd The real file descriptor
   * @param {string} realPath The real filesystem path
   */
  constructor(path, flags, mode, fd, realPath) {
    super(path, flags, mode);
    this.#fd = fd;
    this.#realPath = realPath;
  }

  /**
   * Gets the real file descriptor.
   * @returns {number}
   */
  get fd() {
    return this.#fd;
  }

  readSync(buffer, offset, length, position) {
    this._checkClosed();
    return fs.readSync(this.#fd, buffer, offset, length, position);
  }

  async read(buffer, offset, length, position) {
    this._checkClosed();
    return new Promise((resolve, reject) => {
      fs.read(this.#fd, buffer, offset, length, position, (err, bytesRead) => {
        if (err) reject(err);
        else resolve({ __proto__: null, bytesRead, buffer });
      });
    });
  }

  writeSync(buffer, offset, length, position) {
    this._checkClosed();
    return fs.writeSync(this.#fd, buffer, offset, length, position);
  }

  async write(buffer, offset, length, position) {
    this._checkClosed();
    return new Promise((resolve, reject) => {
      fs.write(this.#fd, buffer, offset, length, position, (err, bytesWritten) => {
        if (err) reject(err);
        else resolve({ __proto__: null, bytesWritten, buffer });
      });
    });
  }

  // XXX(patch): Custom code/changes added for Gondolin
  // node:fs embeds the path passed to a syscall in errno error messages
  // (and in `err.path`). These operations pass the host real path, so an
  // unmodified error would leak the host filesystem layout to callers on
  // the sandboxed side. Remap it back to the VFS path the caller used.
  _scrubError(error) {
    if (!error || typeof error !== 'object') {
      return error;
    }
    if (typeof error.message === 'string') {
      error.message = error.message.split(this.#realPath).join(this.path);
    }
    if (typeof error.path === 'string') {
      error.path = error.path.split(this.#realPath).join(this.path);
    }
    return error;
  }

  readFileSync(options) {
    this._checkClosed();
    try {
      return fs.readFileSync(this.#realPath, options);
    } catch (error) {
      throw this._scrubError(error);
    }
  }

  async readFile(options) {
    this._checkClosed();
    try {
      return await fs.promises.readFile(this.#realPath, options);
    } catch (error) {
      throw this._scrubError(error);
    }
  }

  writeFileSync(data, options) {
    this._checkClosed();
    try {
      fs.writeFileSync(this.#realPath, data, options);
    } catch (error) {
      throw this._scrubError(error);
    }
  }

  async writeFile(data, options) {
    this._checkClosed();
    try {
      return await fs.promises.writeFile(this.#realPath, data, options);
    } catch (error) {
      throw this._scrubError(error);
    }
  }

  statSync(options) {
    this._checkClosed();
    return fs.fstatSync(this.#fd, options);
  }

  async stat(options) {
    this._checkClosed();
    return new Promise((resolve, reject) => {
      fs.fstat(this.#fd, options, (err, stats) => {
        if (err) reject(err);
        else resolve(stats);
      });
    });
  }

  truncateSync(len = 0) {
    this._checkClosed();
    fs.ftruncateSync(this.#fd, len);
  }

  async truncate(len = 0) {
    this._checkClosed();
    return new Promise((resolve, reject) => {
      fs.ftruncate(this.#fd, len, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  closeSync() {
    if (!this.closed) {
      fs.closeSync(this.#fd);
      super.closeSync();
    }
  }

  async close() {
    if (!this.closed) {
      return new Promise((resolve, reject) => {
        fs.close(this.#fd, (err) => {
          if (err) reject(err);
          else {
            super.closeSync();
            resolve();
          }
        });
      });
    }
  }
}

/**
 * A provider that wraps a real filesystem directory.
 * Allows mounting a real directory at a different VFS path.
 */
class RealFSProvider extends VirtualProvider {
  #rootPath;

  /**
   * @param {string} rootPath The real filesystem path to use as root
   */
  constructor(rootPath) {
    super();
    if (typeof rootPath !== 'string' || rootPath === '') {
      throw new ERR_INVALID_ARG_VALUE('rootPath', rootPath, 'must be a non-empty string');
    }
    // XXX(patch): Custom code/changes added for Gondolin
    // Resolve to absolute path and normalize.
    //
    // On macOS (and some Linux setups) common temp paths (e.g. /var/...) may be
    // symlinks into /private/..., which can cause realpath() checks/conversions
    // to incorrectly treat in-root paths as escaped.  Prefer a canonical
    // realpath when available.
    const resolvedRoot = path.resolve(rootPath);
    try {
      this.#rootPath = fs.realpathSync(resolvedRoot);
    } catch {
      this.#rootPath = resolvedRoot;
    }
  }

  /**
   * Gets the root path of this provider.
   * @returns {string}
   */
  get rootPath() {
    return this.#rootPath;
  }

  get readonly() {
    return false;
  }

  get supportsSymlinks() {
    return true;
  }

  // XXX(patch): Custom code/changes added for Gondolin
  // _resolvePathLexical: lexical containment only
  // _resolvePathFollow: lexical + realpath verification
  // _resolvePathNoFollowFinal: validates ancestors via follow checks, but treats final path segment lexically
  _resolvePathLexical(vfsPath) {
    let normalized = vfsPath;
    if (normalized.startsWith('/')) {
      normalized = normalized.slice(1);
    }

    const realPath = path.resolve(this.#rootPath, normalized);

    const rootWithSep = this.#rootPath.endsWith(path.sep) ?
      this.#rootPath :
      this.#rootPath + path.sep;

    if (realPath !== this.#rootPath && !StringPrototypeStartsWith(realPath, rootWithSep)) {
      const { createENOENT } = require('internal/vfs/errors');
      throw createENOENT('open', vfsPath);
    }

    return realPath;
  }

  _isInsideRoot(resolvedPath) {
    if (resolvedPath === this.#rootPath) return true;
    const rootWithSep = this.#rootPath.endsWith(path.sep) ?
      this.#rootPath :
      this.#rootPath + path.sep;
    return StringPrototypeStartsWith(resolvedPath, rootWithSep);
  }

  // XXX(patch): Custom code/changes added for Gondolin
  // node:fs embeds the path passed to a syscall in errno error messages
  // (and in `err.path`). Provider methods pass host-resolved real paths, so
  // an unmodified error would leak the host filesystem layout (the mount
  // root) to callers on the sandboxed side. The resolved real path is always
  // `#rootPath + <vfs path>`, so re-expressing it relative to the mount root
  // ("./<vfs path>", or "." for the root itself) removes the host path while
  // staying unambiguous about what the path is relative to.
  _scrubRealPathsFromError(error) {
    const root = this.#rootPath;
    if (!root || !error || typeof error !== 'object') {
      return error;
    }
    const sep = root.endsWith(path.sep) ? '' : path.sep;
    const scrub = (value) =>
      value.split(root + sep).join('./').split(root).join('.');
    if (typeof error.message === 'string') {
      error.message = scrub(error.message);
    }
    if (typeof error.path === 'string') {
      error.path = scrub(error.path);
    }
    return error;
  }

  _runSync(fn) {
    try {
      return fn();
    } catch (error) {
      throw this._scrubRealPathsFromError(error);
    }
  }

  async _runAsync(fn) {
    try {
      return await fn();
    } catch (error) {
      throw this._scrubRealPathsFromError(error);
    }
  }

  _assertAncestorWithinRoot(realPath, vfsPath) {
    let current = realPath;
    while (true) {
      const parent = path.dirname(current);
      if (parent === current) break; // reached filesystem root

      let resolvedParent = null;
      try {
        resolvedParent = fs.realpathSync(parent);
      } catch (e) {
        if (e && e.code === 'ENOENT') {
          current = parent;
          continue;
        }
        throw this._scrubRealPathsFromError(e);
      }

      if (!this._isInsideRoot(resolvedParent)) {
        const { createENOENT } = require('internal/vfs/errors');
        throw createENOENT('open', vfsPath);
      }
      return; // found a safe existing ancestor
    }
  }

  _resolvePathFollow(vfsPath) {
    const realPath = this._resolvePathLexical(vfsPath);
    const { createENOENT } = require('internal/vfs/errors');

    try {
      const resolved = fs.realpathSync(realPath);
      if (!this._isInsideRoot(resolved)) {
        throw createENOENT('open', vfsPath);
      }
      return realPath;
    } catch (error) {
      if (!error || error.code !== 'ENOENT') {
        throw this._scrubRealPathsFromError(error);
      }
    }

    // Strict mode: if the final entry is a dangling symlink, reject it.
    let lst = null;
    try {
      lst = fs.lstatSync(realPath);
    } catch (error) {
      if (!error || error.code !== 'ENOENT') {
        throw this._scrubRealPathsFromError(error);
      }
    }
    if (lst && lst.isSymbolicLink()) {
      throw createENOENT('open', vfsPath);
    }

    this._assertAncestorWithinRoot(realPath, vfsPath);

    return realPath;
  }

  _resolvePathNoFollowFinal(vfsPath) {
    const realPath = this._resolvePathLexical(vfsPath);
    let normalized = vfsPath;
    if (!normalized.startsWith('/')) {
      normalized = '/' + normalized;
    }
    normalized = path.posix.normalize(normalized);
    const parentVfsPath = path.posix.dirname(normalized);
    this._resolvePathFollow(parentVfsPath);
    return realPath;
  }

  openSync(vfsPath, flags, mode) {
    const realPath = this._resolvePathFollow(vfsPath);
    const fd = this._runSync(() => fs.openSync(realPath, flags, mode));
    return new RealFileHandle(vfsPath, flags, mode ?? 0o644, fd, realPath);
  }

  async open(vfsPath, flags, mode) {
    const realPath = this._resolvePathFollow(vfsPath);
    return new Promise((resolve, reject) => {
      fs.open(realPath, flags, mode, (err, fd) => {
        if (err) reject(this._scrubRealPathsFromError(err));
        else resolve(new RealFileHandle(vfsPath, flags, mode ?? 0o644, fd, realPath));
      });
    });
  }

  statSync(vfsPath, options) {
    const realPath = this._resolvePathFollow(vfsPath);
    return this._runSync(() => fs.statSync(realPath, options));
  }

  async stat(vfsPath, options) {
    const realPath = this._resolvePathFollow(vfsPath);
    return this._runAsync(() => fs.promises.stat(realPath, options));
  }

  lstatSync(vfsPath, options) {
    const realPath = this._resolvePathLexical(vfsPath);
    return this._runSync(() => fs.lstatSync(realPath, options));
  }

  async lstat(vfsPath, options) {
    const realPath = this._resolvePathLexical(vfsPath);
    return this._runAsync(() => fs.promises.lstat(realPath, options));
  }

  readdirSync(vfsPath, options) {
    const realPath = this._resolvePathFollow(vfsPath);
    return this._runSync(() => fs.readdirSync(realPath, options));
  }

  async readdir(vfsPath, options) {
    const realPath = this._resolvePathFollow(vfsPath);
    return this._runAsync(() => fs.promises.readdir(realPath, options));
  }

  mkdirSync(vfsPath, options) {
    const realPath = this._resolvePathFollow(vfsPath);
    return this._runSync(() => fs.mkdirSync(realPath, options));
  }

  async mkdir(vfsPath, options) {
    const realPath = this._resolvePathFollow(vfsPath);
    return this._runAsync(() => fs.promises.mkdir(realPath, options));
  }

  rmdirSync(vfsPath) {
    const realPath = this._resolvePathNoFollowFinal(vfsPath);
    this._runSync(() => fs.rmdirSync(realPath));
  }

  async rmdir(vfsPath) {
    const realPath = this._resolvePathNoFollowFinal(vfsPath);
    return this._runAsync(() => fs.promises.rmdir(realPath));
  }

  unlinkSync(vfsPath) {
    const realPath = this._resolvePathNoFollowFinal(vfsPath);
    this._runSync(() => fs.unlinkSync(realPath));
  }

  async unlink(vfsPath) {
    const realPath = this._resolvePathNoFollowFinal(vfsPath);
    return this._runAsync(() => fs.promises.unlink(realPath));
  }

  renameSync(oldVfsPath, newVfsPath) {
    const oldRealPath = this._resolvePathNoFollowFinal(oldVfsPath);
    const newRealPath = this._resolvePathNoFollowFinal(newVfsPath);
    this._runSync(() => fs.renameSync(oldRealPath, newRealPath));
  }

  async rename(oldVfsPath, newVfsPath) {
    const oldRealPath = this._resolvePathNoFollowFinal(oldVfsPath);
    const newRealPath = this._resolvePathNoFollowFinal(newVfsPath);
    return this._runAsync(() => fs.promises.rename(oldRealPath, newRealPath));
  }

  // XXX(patch): Custom code/changes added for Gondolin
  linkSync(existingVfsPath, newVfsPath) {
    const existingRealPath = this._resolvePathFollow(existingVfsPath);
    const newRealPath = this._resolvePathNoFollowFinal(newVfsPath);
    this._runSync(() => fs.linkSync(existingRealPath, newRealPath));
  }

  async link(existingVfsPath, newVfsPath) {
    const existingRealPath = this._resolvePathFollow(existingVfsPath);
    const newRealPath = this._resolvePathNoFollowFinal(newVfsPath);
    return this._runAsync(() => fs.promises.link(existingRealPath, newRealPath));
  }

  // XXX(patch): Custom code/changes added for Gondolin
  // chmod follows symlinks (like chmod(2)) and is confined to the root.
  // setuid/setgid bits are dropped so guests cannot plant set-id binaries
  // in host directories.
  chmodSync(vfsPath, mode) {
    const realPath = this._resolvePathFollow(vfsPath);
    fs.chmodSync(realPath, mode & kChmodAllowedBits);
  }

  async chmod(vfsPath, mode) {
    const realPath = this._resolvePathFollow(vfsPath);
    return fs.promises.chmod(realPath, mode & kChmodAllowedBits);
  }

  readlinkSync(vfsPath, options) {
    const realPath = this._resolvePathLexical(vfsPath);
    return this._runSync(() => fs.readlinkSync(realPath, options));
  }

  async readlink(vfsPath, options) {
    const realPath = this._resolvePathLexical(vfsPath);
    return this._runAsync(() => fs.promises.readlink(realPath, options));
  }

  symlinkSync(target, vfsPath, type) {
    const realPath = this._resolvePathFollow(vfsPath);
    this._runSync(() => fs.symlinkSync(target, realPath, type));
  }

  async symlink(target, vfsPath, type) {
    const realPath = this._resolvePathFollow(vfsPath);
    return this._runAsync(() => fs.promises.symlink(target, realPath, type));
  }

  realpathSync(vfsPath, options) {
    const realPath = this._resolvePathFollow(vfsPath);
    const resolved = this._runSync(() => fs.realpathSync(realPath, options));
    // Convert back to VFS path
    if (resolved === this.#rootPath) {
      return '/';
    }
    const rootWithSep = this.#rootPath + path.sep;
    if (StringPrototypeStartsWith(resolved, rootWithSep)) {
      return '/' + resolved.slice(rootWithSep.length).replace(/\\/g, '/');
    }
    // Path escaped root (shouldn't happen normally)
    return vfsPath;
  }

  async realpath(vfsPath, options) {
    const realPath = this._resolvePathFollow(vfsPath);
    const resolved = await this._runAsync(() => fs.promises.realpath(realPath, options));
    // Convert back to VFS path
    if (resolved === this.#rootPath) {
      return '/';
    }
    const rootWithSep = this.#rootPath + path.sep;
    if (StringPrototypeStartsWith(resolved, rootWithSep)) {
      return '/' + resolved.slice(rootWithSep.length).replace(/\\/g, '/');
    }
    return vfsPath;
  }

  accessSync(vfsPath, mode) {
    const realPath = this._resolvePathFollow(vfsPath);
    this._runSync(() => fs.accessSync(realPath, mode));
  }

  async access(vfsPath, mode) {
    const realPath = this._resolvePathFollow(vfsPath);
    return this._runAsync(() => fs.promises.access(realPath, mode));
  }

  copyFileSync(srcVfsPath, destVfsPath, mode) {
    const srcRealPath = this._resolvePathFollow(srcVfsPath);
    const destRealPath = this._resolvePathFollow(destVfsPath);
    this._runSync(() => fs.copyFileSync(srcRealPath, destRealPath, mode));
  }

  async copyFile(srcVfsPath, destVfsPath, mode) {
    const srcRealPath = this._resolvePathFollow(srcVfsPath);
    const destRealPath = this._resolvePathFollow(destVfsPath);
    return this._runAsync(() => fs.promises.copyFile(srcRealPath, destRealPath, mode));
  }

  // XXX(patch): Custom code/changes added for Gondolin
  async statfs(vfsPath) {
    if (typeof fs.promises.statfs !== 'function') {
      const err = new Error('ENOSYS: statfs');
      err.code = 'ENOSYS';
      err.errno = ERRNO.ENOSYS;
      throw err;
    }

    const realPath = this._resolvePathFollow(vfsPath);
    const stats = await this._runAsync(() => fs.promises.statfs(realPath));
    const bsize = Number(stats.bsize ?? 4096);

    return {
      blocks: Number(stats.blocks ?? 0),
      bfree: Number(stats.bfree ?? 0),
      bavail: Number(stats.bavail ?? 0),
      files: Number(stats.files ?? 0),
      ffree: Number(stats.ffree ?? 0),
      bsize,
      frsize: Number(stats.frsize ?? bsize),
      namelen: Number(stats.namelen ?? 255),
    };
  }
}

module.exports = {
  RealFSProvider,
  RealFileHandle,
};

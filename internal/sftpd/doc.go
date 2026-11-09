// Package sftpd is the console's built-in SFTP server: a library that runs
// the SFTP protocol on a byte stream, rooted in one directory, with the
// user's .ssh directory out of reach, no symbolic links followed, and an
// audit callback for what the client changes.
//
// A regular file that has more than one name (a hard link, made outside
// SFTP: the server makes none) is not served at all: it cannot be opened,
// read, written or have its attributes set, and the refusal is audited with
// the reason "link". Such a name is still listed, and can be renamed or
// removed, since that acts on the name and never on the data; so a name made
// for the data of a key file in .ssh can be seen and removed, not read or
// changed. The open is judged on the opened file; the setstat check is a look
// at the entry followed by the change, so a name added by something outside
// SFTP in between is not caught.
//
// A session has at most 256 handles open at once, files and directory
// listings together (each holds a descriptor); an open past that fails with a
// failure status and is audited as a refusal ("too many open files"). A
// listing reads the directory as the client asks for the entries, a batch at
// a time, and is not sorted: it comes in the order of the file system.
//
// What the quota guarantees. A write is refused, whole, when it would take the
// usage the session has measured over the limit; that is all. The usage is
// measured when the session starts and again when a file is opened for writing
// and the last measure is more than a few seconds old, and between measures it
// follows what the session itself does. A part of the home the walk could not
// see (a directory without read or search permission, a tree deeper than the
// walk goes, no descriptor left) makes the measure incomplete, and then the
// home counts as full until a later walk is complete: nothing that makes it
// bigger is accepted, while reading, deleting and writing in place go on. A
// removed or replaced file that a handle of the session still has open keeps
// its room until the handle closes. Sessions are independent of each other:
// N sessions of one home that write at once can each use the room that was
// free at their last measure, so the home can come to about N times the
// quota (and programs outside the server write as they like). Only the sizes
// of regular files count, once per inode: not the inodes, the directory
// blocks, the disk blocks (a sparse file counts its length), or what a
// removed file's data takes after the session ended.
//
// The server answers fstat and fsetstat of a handle through the library,
// which looks at the handle's path name and not at the open file. After the
// file was renamed, or its name was given to another file, they act on whatever
// the name is now (or fail), not on the file the handle holds. Confinement does
// not depend on it: the name goes through the same resolution as any path of
// the client (no link followed, nothing outside the home), it can never name
// something in .ssh since a rename into .ssh is refused, and the attribute
// rules of setstat (no owner or size change, the link rule, the directory
// rule) apply to it as to a setstat by path. Reads and writes use the open
// file itself.
//
// It adds no command and prints nothing: a caller (the console) hands it the
// stream of the sftp subsystem and the home directory, and gets a status
// back when the client ends the session.
package sftpd

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
// It adds no command and prints nothing: a caller (the console) hands it the
// stream of the sftp subsystem and the home directory, and gets a status
// back when the client ends the session.
package sftpd

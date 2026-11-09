// Package sftpd is the console's built-in SFTP server: a library that runs
// the SFTP protocol on a byte stream, rooted in one directory, with the
// user's .ssh directory out of reach, no symbolic links followed, and an
// audit callback for what the client changes.
//
// It adds no command and prints nothing: a caller (the console) hands it the
// stream of the sftp subsystem and the home directory, and gets a status
// back when the client ends the session.
package sftpd

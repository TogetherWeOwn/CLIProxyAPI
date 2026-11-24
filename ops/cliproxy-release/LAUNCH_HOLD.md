# Terminal launcher hold

An operation can serialize new terminal CLI launches with a hold through a
participating wrapper. The fixture is the only repository entry point that
calls the adapter. A deployment would require a separate operation to bind
its chosen wrappers and verify terminal caller coverage.

On Linux, the wrapper passes its existing CLI command and arguments to
`python3 -IB launch_hold.py ABSOLUTE_STATE_DIR run COMMAND ...`. The caller
chooses a dedicated mode-0700 directory under a stable parent it controls.
Use the same path for every participating wrapper and for `hold`, `status`,
and `undo`. Keep the directory and lock in place across those commands.
The default is open. A held launch exits with status 75.

The adapter admits a launch by reserving it under the hold lock, then
spawns the CLI before it releases the lock. The child inherits terminal I/O
and the foreground process group. Once the child exists, terminal Ctrl-C
reaches it with the inherited SIGINT disposition while the supervisor keeps
its reservation. The supervisor forwards the exit code and removes the
reservation on ordinary exit. A signalled child or lost supervisor leaves
an unresolved record. Undo reopens launch under the same lock and preserves
outstanding records.

A pre-admitted interactive session can submit more prompts while held,
including when it has no open transport. Wait for its ordinary exit.
`status` reports the hold and the managed record count. A zero count
still requires independent process and transport coverage for unwrapped
callers, prior sessions, and descendants before a cutover. Protected
dispatch and recovery use their existing entry points.

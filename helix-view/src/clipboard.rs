// Implementation reference: https://github.com/neovim/neovim/blob/f2906a4669a2eef6d7bf86a29648793d63c98949/runtime/autoload/provider/clipboard.vim#L68-L152

use std::borrow::Cow;
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub enum ClipboardType {
    Clipboard,
    Selection,
}

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("could not convert terminal output to UTF-8: {0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("clipboard provider command failed")]
    CommandFailed,
    #[error("failed to write to clipboard provider's stdin")]
    StdinWriteFailed,
    #[error("clipboard provider did not return any contents")]
    MissingStdout,
    #[error("This clipboard provider does not support reading")]
    ReadingNotSupported,
}

type Result<T> = std::result::Result<T, ClipboardError>;

#[cfg(not(target_arch = "wasm32"))]
pub use external::ClipboardProvider;
#[cfg(target_arch = "wasm32")]
pub use noop::ClipboardProvider;

#[cfg(target_arch = "wasm32")]
mod noop {
    use super::*;

    #[derive(Debug, Clone)]
    pub enum ClipboardProvider {}

    impl ClipboardProvider {
        pub fn detect() -> Self {
            Self
        }

        pub fn name(&self) -> Cow<str> {
            "none".into()
        }

        pub fn get_contents(&self, _clipboard_type: ClipboardType) -> Result<String> {
            Err(ClipboardError::ReadingNotSupported)
        }

        pub fn set_contents(&self, _content: &str, _clipboard_type: ClipboardType) -> Result<()> {
            Ok(())
        }
    }
}

/// Interaction with external clipboard providers.
#[cfg(not(target_arch = "wasm32"))]
mod external {
    use super::*;

    #[derive(Debug, Default, Clone)]
    pub enum ClipboardProvider {
        Termux,
        Tmux,
        /// MacOS `pbcopy`+`pbpaste`
        Pasteboard,
        /// Wayland clipboard `wl-clipboard`
        WlClipboard,
        XClip,
        XSel,
        Win32Yank,
        #[cfg(target_os = "windows")]
        ClipboardWin,
        /// A provider which uses the OSC52 terminal escape codes.
        /// This provider does not support reading.
        #[cfg(feature = "term")]
        Termcode,
        #[default]
        None,
    }

    impl ClipboardProvider {
        #[cfg(windows)]
        pub fn detect() -> Self {
            if binary_exists("win32yank.exe") {
                Self::Win32Yank
            } else {
                Self::Windows
            }
        }

        #[cfg(target_os = "macos")]
        pub fn detect() -> Self {
            use helix_stdx::env::{binary_exists, env_var_is_set};

            if env_var_is_set("TMUX") && binary_exists("tmux") {
                Self::Tmux
            } else if binary_exists("pbcopy") && binary_exists("pbpaste") {
                Self::Pasteboard
            } else if cfg!(feature = "term") {
                Self::Termcode
            } else {
                Self::default()
            }
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        pub fn detect() -> Self {
            use helix_stdx::env::{binary_exists, env_var_is_set};

            fn is_exit_success(program: &str, args: &[&str]) -> bool {
                std::process::Command::new(program)
                    .args(args)
                    .output()
                    .ok()
                    .and_then(|out| out.status.success().then_some(()))
                    .is_some()
            }

            // TODO: support for user-defined provider, probably when we have plugin support by setting a
            // variable?

            if env_var_is_set("WAYLAND_DISPLAY")
                && binary_exists("wl-copy")
                && binary_exists("wl-paste")
            {
                Self::WlClipboard
            } else if env_var_is_set("DISPLAY") && binary_exists("xclip") {
                Self::XClip
            } else if env_var_is_set("DISPLAY")
                && binary_exists("xsel")
                // FIXME: check performance of is_exit_success
                && is_exit_success("xsel", &["-o", "-b"])
            {
                Self::XSel
            } else if binary_exists("termux-clipboard-set") && binary_exists("termux-clipboard-get")
            {
                Self::Termux
            } else if env_var_is_set("TMUX") && binary_exists("tmux") {
                Self::Tmux
            } else if binary_exists("win32yank.exe") {
                Self::Win32Yank
            } else if cfg!(feature = "term") {
                Self::Termcode
            } else {
                Self::default()
            }
        }

        pub fn name(&self) -> Cow<str> {
            fn builtin_name(provider: CommandProvider<'_>) -> Cow<'_, str> {
                if provider.yank.command != provider.paste.command {
                    Cow::Owned(format!(
                        "{}+{}",
                        provider.yank.command, provider.paste.command
                    ))
                } else {
                    provider.yank.command
                }
            }

            match self {
                Self::Termux => todo!(),
                Self::Tmux => builtin_name(TMUX),
                Self::Pasteboard => builtin_name(PASTEBOARD),
                Self::WlClipboard => builtin_name(WL_CLIPBOARD),
                Self::XClip => todo!(),
                Self::XSel => todo!(),
                Self::Win32Yank => todo!(),
                #[cfg(target_os = "windows")]
                Self::ClipboardWin => "clipboard-win".into(),
                #[cfg(feature = "term")]
                Self::Termcode => "termcode".into(),
                Self::None => "none".into(),
            }
        }

        pub fn get_contents(&self, clipboard_type: ClipboardType) -> Result<String> {
            fn yank_from_builtin(
                provider: CommandProvider,
                clipboard_type: ClipboardType,
            ) -> Result<String> {
                match clipboard_type {
                    ClipboardType::Clipboard => execute_command(&provider.yank, None, true)?
                        .ok_or(ClipboardError::MissingStdout),
                    ClipboardType::Selection => {
                        if let Some(cmd) = provider.yank_primary.as_ref() {
                            return execute_command(cmd, None, true)?
                                .ok_or(ClipboardError::MissingStdout);
                        }

                        Ok(String::new())
                    }
                }
            }

            match self {
                Self::Tmux => yank_from_builtin(TMUX, clipboard_type),
                Self::Pasteboard => yank_from_builtin(PASTEBOARD, clipboard_type),
                Self::WlClipboard => yank_from_builtin(WL_CLIPBOARD, clipboard_type),
                #[cfg(target_os = "windows")]
                Self::ClipboardWin => match clipboard_type {
                    ClipboardType::Clipboard => {
                        let contents =
                            clipboard_win::get_clipboard(clipboard_win::formats::Unicode)?;
                        Ok(contents)
                    }
                    ClipboardType::Selection => Ok(String::new()),
                },
                Self::Termcode | Self::None => Err(ClipboardError::ReadingNotSupported),
                _ => todo!(),
            }
        }

        pub fn set_contents(&self, content: &str, clipboard_type: ClipboardType) -> Result<()> {
            fn paste_to_builtin(
                provider: CommandProvider,
                content: &str,
                clipboard_type: ClipboardType,
            ) -> Result<()> {
                let cmd = match clipboard_type {
                    ClipboardType::Clipboard => &provider.paste,
                    ClipboardType::Selection => {
                        if let Some(cmd) = provider.paste_primary.as_ref() {
                            cmd
                        } else {
                            return Ok(());
                        }
                    }
                };

                execute_command(cmd, Some(content), false).map(|_| ())
            }

            match self {
                Self::Tmux => paste_to_builtin(TMUX, content, clipboard_type),
                Self::Pasteboard => paste_to_builtin(PASTEBOARD, content, clipboard_type),
                Self::WlClipboard => paste_to_builtin(WL_CLIPBOARD, content, clipboard_type),
                #[cfg(target_os = "windows")]
                Self::ClipboardWin => match clipboard_type {
                    ClipboardType::Clipboard => {
                        clipboard_win::set_clipboard(clipboard_win::formats::Unicode, contents)?;
                    }
                    ClipboardType::Selection => (),
                },
                #[cfg(feature = "term")]
                Self::Termcode => {
                    crossterm::queue!(
                        std::io::stdout(),
                        osc52::SetClipboardCommand::new(content, clipboard_type)
                    )?;
                    Ok(())
                }
                Self::None => Ok(()),
                _ => todo!(),
            }
        }
    }

    struct CommandProvider<'a> {
        yank: Command<'a>,
        paste: Command<'a>,
        yank_primary: Option<Command<'a>>,
        paste_primary: Option<Command<'a>>,
    }

    struct Command<'a> {
        command: Cow<'a, str>,
        args: Cow<'a, [Cow<'a, str>]>,
    }

    macro_rules! command_provider {
        ($name:ident,
         yank => $yank_cmd:literal $( , $yank_arg:literal )* ;
         paste => $paste_cmd:literal $( , $paste_arg:literal )* ; ) => {
            const $name: CommandProvider = CommandProvider {
                yank: Command {
                    command: Cow::Borrowed($yank_cmd),
                    args: Cow::Borrowed(&[ $( Cow::Borrowed($yank_arg) ),* ])
                },
                paste: Command {
                    command: Cow::Borrowed($paste_cmd),
                    args: Cow::Borrowed(&[ $( Cow::Borrowed($paste_arg) ),* ])
                },
                yank_primary: None,
                paste_primary: None,
            };
        };
        ($name:ident,
         yank => $yank_cmd:literal $( , $yank_arg:literal )* ;
         paste => $paste_cmd:literal $( , $paste_arg:literal )* ;
         yank_primary => $yank_primary_cmd:literal $( , $yank_primary_arg:literal )* ;
         paste_primary => $paste_primary_cmd:literal $( , $paste_primary_arg:literal )* ; ) => {
            const $name: CommandProvider = CommandProvider {
                yank: Command {
                    command: Cow::Borrowed($yank_cmd),
                    args: Cow::Borrowed(&[ $( Cow::Borrowed($yank_arg) ),* ])
                },
                paste: Command {
                    command: Cow::Borrowed($paste_cmd),
                    args: Cow::Borrowed(&[ $( Cow::Borrowed($paste_arg) ),* ])
                },
                yank_primary: Some(Command {
                    command: Cow::Borrowed($yank_primary_cmd),
                    args: Cow::Borrowed(&[ $( Cow::Borrowed($yank_primary_arg) ),* ])
                }),
                paste_primary: Some(Command {
                    command: Cow::Borrowed($paste_primary_cmd),
                    args: Cow::Borrowed(&[ $( Cow::Borrowed($paste_primary_arg) ),* ])
                }),
            };
        };
    }

    command_provider! {
        TMUX,
        yank => "tmux", "load-buffer", "-w", "-";
        paste => "tmux", "save-buffer", "-";
    }
    command_provider! {
        PASTEBOARD,
        yank => "pbcopy";
        paste => "pbpaste";
    }
    command_provider! {
        WL_CLIPBOARD,
        yank => "wl-copy", "--type", "text/plain";
        paste => "wl-paste", "--no-newline";
        yank_primary => "wl-copy", "-p", "--type", "text/plain";
        paste_primary => "wl-paste", "-p", "--no-newline";
    }

    #[cfg(feature = "term")]
    mod osc52 {
        use {super::ClipboardType, crate::base64};

        #[derive(Debug)]
        pub struct SetClipboardCommand {
            encoded_content: String,
            clipboard_type: ClipboardType,
        }

        impl SetClipboardCommand {
            pub fn new(content: &str, clipboard_type: ClipboardType) -> Self {
                Self {
                    encoded_content: base64::encode(content.as_bytes()),
                    clipboard_type,
                }
            }
        }

        impl crossterm::Command for SetClipboardCommand {
            fn write_ansi(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
                let kind = match &self.clipboard_type {
                    ClipboardType::Clipboard => "c",
                    ClipboardType::Selection => "p",
                };
                // Send an OSC 52 set command: https://terminalguide.namepad.de/seq/osc-52/
                write!(f, "\x1b]52;{};{}\x1b\\", kind, &self.encoded_content)
            }
        }
    }

    fn execute_command(
        cmd: &Command,
        input: Option<&str>,
        pipe_output: bool,
    ) -> Result<Option<String>> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let stdin = input.map(|_| Stdio::piped()).unwrap_or_else(Stdio::null);
        let stdout = pipe_output.then(Stdio::piped).unwrap_or_else(Stdio::null);

        let mut command: Command = Command::new(cmd.command.as_ref());

        let mut command_mut: &mut Command = command
            .args(cmd.args.iter().map(AsRef::as_ref))
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::null());

        // Fix for https://github.com/helix-editor/helix/issues/5424
        if cfg!(unix) {
            use std::os::unix::process::CommandExt;

            unsafe {
                command_mut = command_mut.pre_exec(|| match libc::setsid() {
                    -1 => Err(std::io::Error::last_os_error()),
                    _ => Ok(()),
                });
            }
        }

        let mut child = command_mut.spawn()?;

        if let Some(input) = input {
            let mut stdin = child.stdin.take().ok_or(ClipboardError::StdinWriteFailed)?;
            stdin
                .write_all(input.as_bytes())
                .map_err(|_| ClipboardError::StdinWriteFailed)?;
        }

        // TODO: add timer?
        let output = child.wait_with_output()?;

        if !output.status.success() {
            log::error!(
                "clipboard provider {} failed with stderr: \"{}\"",
                cmd.command.as_ref(),
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(ClipboardError::CommandFailed);
        }

        if pipe_output {
            Ok(Some(String::from_utf8(output.stdout)?))
        } else {
            Ok(None)
        }
    }
}

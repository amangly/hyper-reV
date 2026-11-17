use crate::app::{self, Operation, SetupInput};
use gpui::{
    App, Application, Background, Bounds, BoxShadow, ClipboardItem, Context, Div, FocusHandle,
    FontWeight, KeyBinding, PathPromptOptions, SharedString, Stateful, TitlebarOptions, Window,
    WindowBackgroundAppearance, WindowBounds, WindowControlArea, WindowOptions, actions, div,
    linear_color_stop, linear_gradient, point, prelude::*, px, rgb, rgba, size,
};
use serde_json::Value;
use std::{cell::RefCell, path::PathBuf, rc::Rc};

const INK: u32 = 0x24334b;
const MUTED: u32 = 0x4f6079;
actions!(hyperrev_setup, [FocusNext, FocusPrevious]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Caption {
    Minimize,
    Maximize,
    Close,
}

impl Caption {
    fn area(self) -> WindowControlArea {
        match self {
            Self::Minimize => WindowControlArea::Min,
            Self::Maximize => WindowControlArea::Max,
            Self::Close => WindowControlArea::Close,
        }
    }
    fn glyph(self, maximized: bool) -> &'static str {
        match self {
            Self::Minimize => "\u{e921}",
            Self::Maximize if maximized => "\u{e923}",
            Self::Maximize => "\u{e922}",
            Self::Close => "\u{e8bb}",
        }
    }
    fn label(self, maximized: bool) -> &'static str {
        match self {
            Self::Minimize => "Minimize",
            Self::Maximize if maximized => "Restore window",
            Self::Maximize => "Maximize",
            Self::Close => "Close",
        }
    }
    fn enabled(self, busy: bool) -> bool {
        self != Self::Close || !busy
    }
}

fn gradient(from: u32, to: u32) -> Background {
    linear_gradient(
        165.,
        linear_color_stop(rgba(from), 0.),
        linear_color_stop(rgba(to), 1.),
    )
}

fn elevation(color: u32, offset: f32, blur: f32) -> BoxShadow {
    BoxShadow {
        color: rgba(color).into(),
        offset: point(px(0.), px(offset)),
        blur_radius: px(blur),
        spread_radius: px(-2.),
    }
}

fn window_material(solid: bool) -> WindowBackgroundAppearance {
    if solid {
        WindowBackgroundAppearance::Opaque
    } else {
        WindowBackgroundAppearance::Blurred
    }
}

fn prefer_solid_material() -> bool {
    #[cfg(windows)]
    {
        use std::mem::size_of;
        use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SPI_GETHIGHCONTRAST, SystemParametersInfoW,
        };
        let mut contrast = HIGHCONTRASTW {
            cbSize: size_of::<HIGHCONTRASTW>() as u32,
            ..Default::default()
        };
        let contrast_read = unsafe {
            SystemParametersInfoW(
                SPI_GETHIGHCONTRAST,
                contrast.cbSize,
                (&mut contrast as *mut HIGHCONTRASTW).cast(),
                0,
            )
        };
        contrast_read == 0 || contrast.dwFlags & HCF_HIGHCONTRASTON != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

struct CaptionTip(&'static str);
impl Render for CaptionTip {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .px_2()
            .py_1()
            .rounded(px(6.))
            .bg(rgb(0x26344b))
            .text_color(rgb(0xffffff))
            .font_family("Segoe UI")
            .text_size(px(11.))
            .child(self.0)
    }
}

#[derive(Clone, Copy)]
enum Action {
    Setup,
    Restore,
    Advanced,
    Source,
    Esp,
    Journal,
    Reset,
    Inspect,
    Copy,
}

struct SetupWindow {
    title: SharedString,
    input: SetupInput,
    focus: FocusHandle,
    busy: bool,
    advanced: bool,
    failed: bool,
    solid: bool,
    status: SharedString,
    details: SharedString,
}

impl SetupWindow {
    fn new(title: &'static str, solid: bool, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus = cx.focus_handle();
        focus.focus(window);
        Self {
            title: title.into(),
            input: app::default_input(),
            focus,
            busy: false,
            advanced: false,
            failed: false,
            solid,
            status: "Checking…".into(),
            details: "".into(),
        }
    }

    fn dispatch(&mut self, action: Action, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        match action {
            Action::Setup => self.perform(Operation::Setup, cx),
            Action::Restore => self.perform(Operation::Restore, cx),
            Action::Inspect => self.perform(Operation::Inspect, cx),
            Action::Advanced => {
                self.advanced = !self.advanced;
                cx.notify();
            }
            Action::Source | Action::Esp | Action::Journal => self.pick(action, cx),
            Action::Reset => {
                self.input = app::default_input();
                cx.notify();
            }
            Action::Copy => {
                cx.write_to_clipboard(ClipboardItem::new_string(self.details.to_string()))
            }
        }
    }

    fn perform(&mut self, operation: Operation, cx: &mut Context<Self>) {
        self.busy = true;
        self.failed = false;
        self.status = match operation {
            Operation::Inspect => "Checking…",
            Operation::Setup | Operation::Apply | Operation::Plan => "Setting up…",
            Operation::Restore => "Restoring…",
        }
        .into();
        let input = self.input.clone();
        let worker = cx.background_executor().spawn(async move {
            app::perform(operation, input).map_err(|error| format!("{error:#}"))
        });
        cx.spawn(async move |view, cx| {
            let result = worker.await;
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                match result {
                    Ok(report) => {
                        let (status, failed) = report_status(operation, &report);
                        view.status = status.into();
                        view.failed = failed;
                        if let Some(path) = journal_path(&report) {
                            view.input.journal = path;
                        }
                        view.details = report.into();
                    }
                    Err(error) => {
                        view.status = brief_error(&error).into();
                        view.failed = true;
                        view.details = error.into();
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn pick(&mut self, target: Action, cx: &mut Context<Self>) {
        self.busy = true;
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: matches!(target, Action::Journal),
            directories: !matches!(target, Action::Journal),
            multiple: false,
            prompt: Some(
                match target {
                    Action::Source => "Boot files",
                    Action::Esp => "ESP root",
                    _ => "Recovery journal",
                }
                .into(),
            ),
        });
        cx.spawn(async move |view, cx| {
            let result = match receiver.await {
                Ok(Ok(paths)) => Ok(paths.and_then(|paths| paths.into_iter().next())),
                Ok(Err(error)) => Err(error.to_string()),
                Err(error) => Err(error.to_string()),
            };
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                match result {
                    Ok(Some(path)) => match target {
                        Action::Source => view.input.source = path,
                        Action::Esp => view.input.esp = Some(path),
                        Action::Journal => view.input.journal = path,
                        _ => {}
                    },
                    Ok(None) => {}
                    Err(error) => {
                        view.status = brief_error(&error).into();
                        view.failed = true;
                        view.details = error.into();
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn button(
        &self,
        id: &'static str,
        label: &'static str,
        action: Action,
        primary: bool,
        cx: &Context<Self>,
    ) -> Stateful<Div> {
        div()
            .id(id)
            .flex()
            .items_center()
            .justify_center()
            .h(px(44.))
            .px_6()
            .rounded_full()
            .border_1()
            .border_color(rgba(if self.solid { 0x8b9bb5ff } else { 0xffffffd9 }))
            .bg(if primary {
                gradient(0x2365dbff, 0x124fc6f0)
            } else if self.solid {
                gradient(0xffffffff, 0xffffffff)
            } else {
                gradient(0xffffffdc, 0xffffff70)
            })
            .shadow(vec![elevation(
                if primary { 0x205dc53b } else { 0x2a42621f },
                5.,
                14.,
            )])
            .text_color(rgb(if primary { 0xffffff } else { INK }))
            .text_size(px(13.))
            .font_weight(FontWeight::SEMIBOLD)
            .child(label)
            .when(self.busy, |button| button.opacity(0.45))
            .when(!self.busy, |button| {
                button
                    .focusable()
                    .tab_stop(true)
                    .tab_index(0)
                    .cursor_pointer()
                    .hover(move |style| {
                        style.bg(if primary {
                            gradient(0x195bd7ff, 0x1648bafc)
                        } else {
                            gradient(0xfffffff5, 0xffffffb8)
                        })
                    })
                    .active(move |style| {
                        style.bg(if primary {
                            gradient(0x144abaff, 0x123da5ff)
                        } else {
                            gradient(0xe5edfbf0, 0xffffffd0)
                        })
                    })
                    .focus(|style| style.border_color(rgb(0x1849ac)).border_2())
                    .on_click(cx.listener(move |view, _, _, cx| view.dispatch(action, cx)))
                    .on_key_down(cx.listener(move |view, event: &gpui::KeyDownEvent, _, cx| {
                        if matches!(event.keystroke.key.as_str(), "enter" | "space") {
                            cx.stop_propagation();
                            view.dispatch(action, cx);
                        }
                    }))
            })
    }

    fn path_row(
        &self,
        id: &'static str,
        label: &'static str,
        value: String,
        action: Action,
        cx: &Context<Self>,
    ) -> Div {
        div()
            .flex()
            .items_center()
            .gap_3()
            .child(div().w(px(52.)).text_color(rgb(MUTED)).child(label))
            .child(
                div()
                    .id(id)
                    .flex_1()
                    .min_w_0()
                    .overflow_x_scroll()
                    .whitespace_nowrap()
                    .font_family("Consolas")
                    .text_size(px(11.))
                    .child(value),
            )
            .child(
                self.button(
                    match action {
                        Action::Source => "browse-source",
                        Action::Esp => "browse-esp",
                        _ => "browse-journal",
                    },
                    "Browse",
                    action,
                    false,
                    cx,
                )
                .h(px(28.))
                .px_2()
                .text_size(px(11.)),
            )
    }

    fn advanced(&self, cx: &Context<Self>) -> Div {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .w_full()
            .p_4()
            .rounded(px(18.))
            .border_1()
            .border_color(rgba(if self.solid { 0x9cacc2ff } else { 0xffffffbf }))
            .bg(rgba(if self.solid { 0xffffffff } else { 0xffffff8c }))
            .child(self.path_row(
                "source-path",
                "Files",
                self.input.source.display().to_string(),
                Action::Source,
                cx,
            ))
            .child(
                self.path_row(
                    "esp-path",
                    "ESP",
                    self.input
                        .esp
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "Automatic".into()),
                    Action::Esp,
                    cx,
                ),
            )
            .child(self.path_row(
                "journal-path",
                "Journal",
                self.input.journal.display().to_string(),
                Action::Journal,
                cx,
            ))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        self.button("reset", "Defaults", Action::Reset, false, cx)
                            .h(px(28.))
                            .px_2()
                            .text_size(px(11.)),
                    )
                    .child(
                        self.button("inspect", "Refresh", Action::Inspect, false, cx)
                            .h(px(28.))
                            .px_2()
                            .text_size(px(11.)),
                    )
                    .child(
                        self.button("copy", "Copy details", Action::Copy, false, cx)
                            .h(px(28.))
                            .px_2()
                            .text_size(px(11.)),
                    ),
            )
            .child(
                div()
                    .id("diagnostics")
                    .h(px(180.))
                    .w_full()
                    .overflow_y_scroll()
                    .p_3()
                    .rounded(px(12.))
                    .bg(rgba(if self.solid { 0xedf1f8ff } else { 0xecf2fb9e }))
                    .font_family("Consolas")
                    .text_size(px(10.))
                    .whitespace_normal()
                    .child(self.details.clone()),
            )
    }
}

impl SetupWindow {
    fn caption(&self, control: Caption, window: &Window) -> Stateful<Div> {
        let maximized = window.is_maximized();
        let label = control.label(maximized);
        // Native non-client areas retain drag, snap, maximize/restore and WM_CLOSE.
        // Focus handlers here would consume non-client MouseDown in GPUI 0.2.2.
        div()
            .id(match control {
                Caption::Minimize => "caption-minimize",
                Caption::Maximize => "caption-maximize",
                Caption::Close => "caption-close",
            })
            .window_control_area(control.area())
            .w(px(34.))
            .h(px(28.))
            .flex()
            .items_center()
            .justify_center()
            .rounded_full()
            .font_family("Segoe MDL2 Assets")
            .text_size(px(10.))
            .text_color(rgb(INK))
            .child(control.glyph(maximized))
            .when(!control.enabled(self.busy), |button| button.opacity(0.4))
            .hover(move |style| {
                if control == Caption::Close {
                    style.bg(rgba(0xea4764e8)).text_color(rgb(0xffffff))
                } else {
                    style.bg(rgba(0xffffffb8))
                }
            })
            .tooltip(move |_, cx| cx.new(|_| CaptionTip(label)).into())
    }

    fn titlebar(&self, window: &Window) -> Div {
        div()
            .h(px(52.))
            .w_full()
            .flex_shrink_0()
            .flex()
            .items_center()
            .gap_3()
            .pt(px(8.))
            .pb(px(6.))
            .px(px(12.))
            .child(
                div()
                    .id("window-drag")
                    .window_control_area(WindowControlArea::Drag)
                    .flex_1()
                    .h_full()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pl_2()
                    .child(
                        div()
                            .size(px(22.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(7.))
                            .border_1()
                            .border_color(rgba(0xffffffb3))
                            .bg(gradient(0x3477e6ff, 0x174dbdff))
                            .text_color(rgb(0xffffff))
                            .text_size(px(13.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(self.title.chars().next().unwrap_or('E').to_string()),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(if window.is_window_active() {
                                INK
                            } else {
                                MUTED
                            }))
                            .child(self.title.clone()),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_1()
                    .p(px(3.))
                    .rounded_full()
                    .border_1()
                    .border_color(rgba(if self.solid { 0x9cacc2ff } else { 0xffffffc7 }))
                    .bg(if self.solid {
                        gradient(0xffffffff, 0xffffffff)
                    } else {
                        gradient(0xffffffbd, 0xffffff54)
                    })
                    .shadow(vec![elevation(0x354d721c, 3., 10.)])
                    .child(self.caption(Caption::Minimize, window))
                    .child(self.caption(Caption::Maximize, window))
                    .child(self.caption(Caption::Close, window)),
            )
    }
}

impl Render for SetupWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("glass-window")
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .overflow_hidden()
            .font_family("Segoe UI")
            .text_size(px(12.))
            .text_color(rgb(INK))
            .bg(if self.solid {
                gradient(0xeff3faff, 0xf7f9fcff)
            } else {
                gradient(0xe5efffdc, 0xf6edf9d4)
            })
            .when(!window.is_maximized(), |view| view.rounded(px(12.)))
            .when(!self.solid, |view| {
                view.child(
                    div()
                        .absolute()
                        .size(px(250.))
                        .top(px(-170.))
                        .right(px(-100.))
                        .rounded_full()
                        .bg(rgba(0xb8c4ff25))
                        .shadow(vec![elevation(0xb8c4ff38, 0., 90.)]),
                )
                .child(
                    div()
                        .absolute()
                        .size(px(220.))
                        .bottom(px(-170.))
                        .left(px(-70.))
                        .rounded_full()
                        .bg(rgba(0x8ccaff24))
                        .shadow(vec![elevation(0x8ccaff38, 0., 95.)]),
                )
            })
            .child(self.titlebar(window))
            // Keep native caption areas outside every focus-tracked ancestor.
            .child(
                div()
                    .id("setup")
                    .key_context("HyperReVSetup")
                    .track_focus(&self.focus)
                    .on_action(cx.listener(|_, _: &FocusNext, window, _| window.focus_next()))
                    .on_action(cx.listener(|_, _: &FocusPrevious, window, _| window.focus_prev()))
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_4()
                    .p_6()
                    .overflow_y_scroll()
                    .when(!self.advanced, |view| view.justify_center())
                    .child(
                        div()
                            .text_size(px(28.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(self.title.clone()),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .items_center()
                            .gap_4()
                            .p_5()
                            .rounded(px(28.))
                            .border_1()
                            .border_color(rgba(if self.solid { 0x9cacc2ff } else { 0xffffffdb }))
                            .bg(if self.solid {
                                gradient(0xffffffff, 0xffffffff)
                            } else {
                                gradient(0xffffff9c, 0xffffff3d)
                            })
                            .shadow(vec![
                                elevation(0x354f7826, 10., 30.),
                                elevation(0xffffff80, -1., 2.),
                            ])
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .child(
                                        self.button(
                                            "setup-button",
                                            "Setup",
                                            Action::Setup,
                                            true,
                                            cx,
                                        )
                                        .w(px(160.)),
                                    )
                                    .child(
                                        self.button(
                                            "restore-button",
                                            "Restore",
                                            Action::Restore,
                                            false,
                                            cx,
                                        )
                                        .w(px(120.)),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .max_w(px(320.))
                                    .px_3()
                                    .py_1()
                                    .rounded_full()
                                    .bg(rgba(if self.solid { 0xf0f4faff } else { 0xffffff70 }))
                                    .child(div().size(px(5.)).rounded_full().bg(rgb(
                                        if self.failed {
                                            0xb52c48
                                        } else if self.busy {
                                            0x4275c1
                                        } else {
                                            0x27816a
                                        },
                                    )))
                                    .child(
                                        div()
                                            .text_size(px(11.))
                                            .text_color(rgb(if self.failed {
                                                0x9b2442
                                            } else {
                                                MUTED
                                            }))
                                            .child(self.status.clone()),
                                    ),
                            ),
                    )
                    .child(
                        self.button(
                            "advanced",
                            if self.advanced {
                                "Hide advanced"
                            } else {
                                "Advanced"
                            },
                            Action::Advanced,
                            false,
                            cx,
                        )
                        .h(px(26.))
                        .px_3()
                        .border_0()
                        .shadow(Vec::new())
                        .bg(rgba(0xffffff00))
                        .font_weight(FontWeight::MEDIUM)
                        .text_size(px(11.))
                        .text_color(rgb(MUTED)),
                    )
                    .when(self.advanced, |view| view.child(self.advanced(cx))),
            )
    }
}

fn journal_path(report: &str) -> Option<PathBuf> {
    let value: Value = serde_json::from_str(report).ok()?;
    value
        .get("journal_path")?
        .as_str()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
}

fn report_status(operation: Operation, report: &str) -> (String, bool) {
    let value: Value = match serde_json::from_str(report) {
        Ok(value) => value,
        Err(_) => return ("Invalid response".into(), true),
    };
    if let Some(error) = value.get("firmware_error").and_then(Value::as_str) {
        return (brief_error(error), true);
    }
    let text = match operation {
        Operation::Inspect => {
            let machine = &value["machine"];
            if machine["firmware"].as_str() != Some("UEFI") {
                "UEFI required"
            } else if machine["secure_boot"].as_bool() == Some(true) {
                "Secure Boot is on"
            } else if machine["hyperv_available"].as_bool() == Some(false) {
                "Hyper-V is missing"
            } else {
                "Ready"
            }
        }
        Operation::Setup | Operation::Apply
            if value["already_configured"].as_bool() == Some(true) =>
        {
            "Already set up"
        }
        Operation::Setup | Operation::Apply => "Installed. Restart when ready.",
        Operation::Restore => "Restored",
        Operation::Plan => "Plan saved",
    };
    (text.into(), false)
}

fn brief_error(error: &str) -> String {
    let line = error.lines().next().unwrap_or("Operation failed").trim();
    let shortened: String = line.chars().take(110).collect();
    if line.chars().count() > 110 {
        format!("{shortened}…")
    } else {
        shortened
    }
}

pub fn run() -> anyhow::Result<()> {
    run_with_title("hyper-reV")
}

pub fn run_with_title(title: &'static str) -> anyhow::Result<()> {
    let solid = prefer_solid_material();
    let failure = Rc::new(RefCell::new(None));
    let failure_slot = failure.clone();
    Application::new().run(move |cx: &mut App| {
        cx.bind_keys([
            KeyBinding::new("tab", FocusNext, Some("HyperReVSetup")),
            KeyBinding::new("shift-tab", FocusPrevious, Some("HyperReVSetup")),
        ]);
        let bounds = Bounds::centered(None, size(px(560.), px(360.)), cx);
        let opened = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(480.), px(340.))),
                window_background: window_material(solid),
                titlebar: Some(TitlebarOptions {
                    title: Some(title.into()),
                    appears_transparent: true,
                    ..Default::default()
                }),
                app_id: Some(format!(
                    "{}.setup",
                    title.to_ascii_lowercase().replace(' ', "-")
                )),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(|cx| {
                    let mut view = SetupWindow::new(title, solid, window, cx);
                    view.perform(Operation::Inspect, cx);
                    view
                });
                let weak = view.downgrade();
                window.on_window_should_close(cx, move |_, cx| {
                    weak.update(cx, |view, _| Caption::Close.enabled(view.busy))
                        .unwrap_or(true)
                });
                view
            },
        );
        match opened {
            Ok(_) => {
                cx.on_window_closed(|cx| {
                    if cx.windows().is_empty() {
                        cx.quit();
                    }
                })
                .detach();
                cx.activate(true);
            }
            Err(error) => {
                *failure_slot.borrow_mut() = Some(error);
                cx.quit();
            }
        }
    });
    match failure.borrow_mut().take() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caption_controls_use_native_window_actions() {
        assert_eq!(Caption::Minimize.area(), WindowControlArea::Min);
        assert_eq!(Caption::Maximize.area(), WindowControlArea::Max);
        assert_eq!(Caption::Close.area(), WindowControlArea::Close);
    }
    #[test]
    fn maximized_caption_changes_to_restore() {
        assert_ne!(
            Caption::Maximize.glyph(false),
            Caption::Maximize.glyph(true)
        );
        assert_eq!(Caption::Maximize.label(true), "Restore window");
        assert_eq!(Caption::Maximize.label(false), "Maximize");
    }
    #[test]
    fn active_operations_keep_close_guarded_and_window_management_available() {
        assert!(!Caption::Close.enabled(true));
        assert!(Caption::Close.enabled(false));
        assert!(Caption::Minimize.enabled(true));
        assert!(Caption::Maximize.enabled(true));
    }
    #[test]
    fn solid_material_uses_an_opaque_window() {
        assert_eq!(window_material(true), WindowBackgroundAppearance::Opaque);
        assert_eq!(window_material(false), WindowBackgroundAppearance::Blurred);
    }
    #[test]
    fn ready_has_a_single_short_status() {
        let report =
            r#"{"machine":{"firmware":"UEFI","secure_boot":false,"hyperv_available":true}}"#;
        assert_eq!(
            report_status(Operation::Inspect, report),
            ("Ready".into(), false)
        );
    }
    #[test]
    fn setup_has_a_short_completion_status() {
        assert_eq!(
            report_status(Operation::Setup, "{}"),
            ("Installed. Restart when ready.".into(), false)
        );
    }
    #[test]
    fn repeat_setup_is_distinct() {
        assert_eq!(
            report_status(Operation::Setup, r#"{"already_configured":true}"#).0,
            "Already set up"
        );
    }
    #[test]
    fn restore_has_a_short_completion_status() {
        assert_eq!(report_status(Operation::Restore, "{}").0, "Restored");
    }
    #[test]
    fn firmware_errors_remain_visible() {
        assert_eq!(
            report_status(Operation::Inspect, r#"{"firmware_error":"Read failed"}"#),
            ("Read failed".into(), true)
        );
    }
    #[test]
    fn invalid_json_is_an_error() {
        assert!(report_status(Operation::Inspect, "invalid").1);
    }
    #[test]
    fn long_errors_stay_compact_and_unicode_safe() {
        assert_eq!(brief_error("first\nsecond"), "first");
        assert_eq!(brief_error(&"é".repeat(200)).chars().count(), 111);
    }
    #[test]
    fn recovery_path_comes_from_the_actual_report() {
        assert_eq!(
            journal_path(r#"{"journal_path":"C:\\state\\boot.json"}"#),
            Some(PathBuf::from(r"C:\state\boot.json"))
        );
        assert!(journal_path(r#"{"journal_path":" "}"#).is_none());
    }
}

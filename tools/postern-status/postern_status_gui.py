#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Desktop window for the read-only Postern privacy status report.

Presentation only: every observation comes from postern_status.collect(), so
the window and the command-line tool cannot disagree.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "lib", "postern-status"))
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk  # noqa: E402

import postern_status as status  # noqa: E402

APP_ID = "org.postern.Status"
LOOK = {
    status.OK: ("object-select-symbolic", "success"),
    status.WARN: ("dialog-warning-symbolic", "warning"),
    status.FAIL: ("dialog-error-symbolic", "error"),
    status.UNKNOWN: ("dialog-question-symbolic", "dim-label"),
}


def headline(summary):
    """Title, icon and style for the banner; failures always dominate."""
    if summary[status.FAIL]:
        return "Privacy baseline has failed checks", "dialog-error-symbolic", "error"
    if summary[status.WARN] or summary[status.UNKNOWN]:
        return "Privacy baseline observed, with notes", "security-medium-symbolic", "warning"
    return "Privacy baseline observed", "security-high-symbolic", "success"


def counts(summary):
    return (f"{summary[status.OK]} ok  ·  {summary[status.WARN]} warning(s)  ·  "
            f"{summary[status.FAIL]} failed  ·  {summary[status.UNKNOWN]} not determined")


class Window(Adw.ApplicationWindow):
    def __init__(self, application):
        super().__init__(application=application, title="Postern Status")
        self.set_default_size(620, 660)
        # Narrow enough for a phone: every label below wraps instead of widening.
        self.set_size_request(320, 360)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Check again")
        refresh.connect("clicked", lambda _button: self.reload())
        header = Adw.HeaderBar()
        header.pack_start(refresh)
        self.page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24,
                            margin_top=28, margin_bottom=28, margin_start=18, margin_end=18)
        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        scroller.set_child(Adw.Clamp(maximum_size=680, child=self.page))
        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(scroller)
        self.set_content(view)
        self.reload()

    def reload(self):
        while self.page.get_first_child() is not None:
            self.page.remove(self.page.get_first_child())
        report = status.collect(status.Probe("/"))
        title, icon_name, style = headline(report["summary"])

        banner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        icon = Gtk.Image(icon_name=icon_name, pixel_size=72)
        icon.add_css_class(style)
        banner.append(icon)
        heading = Gtk.Label(label=title, wrap=True, justify=Gtk.Justification.CENTER)
        heading.add_css_class("title-2")
        banner.append(heading)
        tally = Gtk.Label(label=counts(report["summary"]), wrap=True,
                          justify=Gtk.Justification.CENTER)
        tally.add_css_class("dim-label")
        banner.append(tally)
        self.page.append(banner)

        group = Adw.PreferencesGroup()
        for item in report["checks"]:
            mark, mark_style = LOOK[item["state"]]
            row = Adw.ActionRow(title=item["title"], subtitle=item["detail"],
                                use_markup=False, title_lines=0, subtitle_lines=0)
            image = Gtk.Image(icon_name=mark, pixel_size=20)
            image.add_css_class(mark_style)
            row.add_prefix(image)
            group.add(row)
        self.page.append(group)

        scope = Gtk.Label(label=report["scope"] + "\nDetails: /etc/postern/privacy.txt",
                          wrap=True, justify=Gtk.Justification.CENTER)
        scope.add_css_class("dim-label")
        scope.add_css_class("caption")
        self.page.append(scope)


def main(argv=None):
    application = Adw.Application(application_id=APP_ID,
                                  flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
    application.connect("activate", lambda app: (app.get_active_window() or Window(app)).present())
    return application.run(argv if argv is not None else sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())

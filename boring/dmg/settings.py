# dmgbuild settings for the Boring Remote Mac DMG. boring/dmg/release-mac.sh runs:
#   dmgbuild -s boring/dmg/settings.py -D app=<BoringRemote.app> -D art=boring/dmg "Boring Remote" out.dmg
# Art: background.png + background@2x.png next to this file (boring/dmg/make_art.py);
# dmgbuild finds the @2x file and joins both into one HiDPI TIFF.
# House DMG minimum: sized window, no toolbar/sidebar/path bar/status bar, app left,
# Applications right (the art draws the arrow between them), volume icon = app icon.
import os

app = defines["app"]  # noqa: F821  (dmgbuild injects `defines`)
name = os.path.basename(app)
here = defines.get("art", os.path.abspath("boring/dmg"))  # noqa: F821  (folder with the art)

format = "UDZO"
filesystem = "HFS+"
files = [app]
symlinks = {"Applications": "/Applications"}
icon = os.path.join(app, "Contents", "Resources", "AppIcon.icns")
background = os.path.join(here, "background.png")

show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
sidebar_width = 0
window_rect = ((200, 120), (640, 468))  # 440 of art + the title bar
default_view = "icon-view"
show_icon_preview = False
include_icon_view_settings = True
icon_size = 96
text_size = 13
arrange_by = None
icon_locations = {name: (160, 178), "Applications": (480, 178)}  # match make_art.py

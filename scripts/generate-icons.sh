#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SVG="$ROOT/src/static/logo.svg"
OUT="$ROOT/icons"

if ! command -v magick &> /dev/null; then
  echo "ImageMagick required: brew install imagemagick"
  exit 1
fi

echo "Generating icons from $SVG..."

TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

# Render SVG to high-res PNG with white background, centered
magick -density 300 -background white "$SVG" -resize 700x700 \
  -gravity center -extent 1024x1024 "$TMP/base.png"

# Main icon (RGBA required by Tauri)
magick "$TMP/base.png" -type TrueColorAlpha PNG32:"$OUT/icon.png"

# Standard sizes (RGBA required by Tauri)
for size in 32 64 128 256 512; do
  magick "$TMP/base.png" -resize ${size}x${size} -type TrueColorAlpha PNG32:"$OUT/${size}x${size}.png"
done

# Retina
magick "$TMP/base.png" -resize 256x256 -type TrueColorAlpha PNG32:"$OUT/128x128@2x.png"

# macOS .icns (run script in terminal, not sandbox, for iconutil to work)
if command -v iconutil &> /dev/null; then
  ICONSET="$TMP/icon.iconset"
  mkdir -p "$ICONSET"
  magick "$TMP/base.png" -resize 16x16   "$ICONSET/icon_16x16.png"
  magick "$TMP/base.png" -resize 32x32   "$ICONSET/icon_16x16@2x.png"
  magick "$TMP/base.png" -resize 32x32   "$ICONSET/icon_32x32.png"
  magick "$TMP/base.png" -resize 64x64   "$ICONSET/icon_32x32@2x.png"
  magick "$TMP/base.png" -resize 128x128 "$ICONSET/icon_128x128.png"
  magick "$TMP/base.png" -resize 256x256 "$ICONSET/icon_128x128@2x.png"
  magick "$TMP/base.png" -resize 256x256 "$ICONSET/icon_256x256.png"
  magick "$TMP/base.png" -resize 512x512 "$ICONSET/icon_256x256@2x.png"
  magick "$TMP/base.png" -resize 512x512 "$ICONSET/icon_512x512.png"
  magick "$TMP/base.png" -resize 1024x1024 "$ICONSET/icon_512x512@2x.png"
  iconutil -c icns "$ICONSET" -o "$OUT/icon.icns" && echo "Created icon.icns" || echo "iconutil failed (run in terminal, not sandboxed)"
fi

# Windows .ico
magick "$TMP/base.png" -define icon:auto-resize=256,128,64,48,32,16 "$OUT/icon.ico"
echo "Created icon.ico"

# Windows Store
for size in 30 44 71 89 107 142 150 284 310; do
  magick "$TMP/base.png" -resize ${size}x${size} "$OUT/Square${size}x${size}Logo.png"
done
magick "$TMP/base.png" -resize 50x50 "$OUT/StoreLogo.png"

# iOS
mkdir -p "$OUT/ios"
magick "$TMP/base.png" -resize 20x20   "$OUT/ios/AppIcon-20x20@1x.png"
magick "$TMP/base.png" -resize 40x40   "$OUT/ios/AppIcon-20x20@2x.png"
magick "$TMP/base.png" -resize 40x40   "$OUT/ios/AppIcon-20x20@2x-1.png"
magick "$TMP/base.png" -resize 60x60   "$OUT/ios/AppIcon-20x20@3x.png"
magick "$TMP/base.png" -resize 29x29   "$OUT/ios/AppIcon-29x29@1x.png"
magick "$TMP/base.png" -resize 58x58   "$OUT/ios/AppIcon-29x29@2x.png"
magick "$TMP/base.png" -resize 58x58   "$OUT/ios/AppIcon-29x29@2x-1.png"
magick "$TMP/base.png" -resize 87x87   "$OUT/ios/AppIcon-29x29@3x.png"
magick "$TMP/base.png" -resize 40x40   "$OUT/ios/AppIcon-40x40@1x.png"
magick "$TMP/base.png" -resize 80x80   "$OUT/ios/AppIcon-40x40@2x.png"
magick "$TMP/base.png" -resize 80x80   "$OUT/ios/AppIcon-40x40@2x-1.png"
magick "$TMP/base.png" -resize 120x120 "$OUT/ios/AppIcon-40x40@3x.png"
magick "$TMP/base.png" -resize 120x120 "$OUT/ios/AppIcon-60x60@2x.png"
magick "$TMP/base.png" -resize 180x180 "$OUT/ios/AppIcon-60x60@3x.png"
magick "$TMP/base.png" -resize 76x76   "$OUT/ios/AppIcon-76x76@1x.png"
magick "$TMP/base.png" -resize 152x152 "$OUT/ios/AppIcon-76x76@2x.png"
magick "$TMP/base.png" -resize 167x167 "$OUT/ios/AppIcon-83.5x83.5@2x.png"
magick "$TMP/base.png" -resize 1024x1024 "$OUT/ios/AppIcon-512@2x.png"

# Android
mkdir -p "$OUT/android/mipmap-"{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}
mkdir -p "$OUT/android/mipmap-anydpi-v26"
mkdir -p "$OUT/android/values"

# Android standard icons
magick "$TMP/base.png" -resize 48x48   "$OUT/android/mipmap-mdpi/ic_launcher.png"
magick "$TMP/base.png" -resize 72x72   "$OUT/android/mipmap-hdpi/ic_launcher.png"
magick "$TMP/base.png" -resize 96x96   "$OUT/android/mipmap-xhdpi/ic_launcher.png"
magick "$TMP/base.png" -resize 144x144 "$OUT/android/mipmap-xxhdpi/ic_launcher.png"
magick "$TMP/base.png" -resize 192x192 "$OUT/android/mipmap-xxxhdpi/ic_launcher.png"

# Android round icons (simple circle crop)
for dir_size in "mdpi:48" "hdpi:72" "xhdpi:96" "xxhdpi:144" "xxxhdpi:192"; do
  dir="${dir_size%%:*}"
  size="${dir_size##*:}"
  magick "$TMP/base.png" -resize ${size}x${size} \
    \( +clone -alpha extract -draw "fill black polygon 0,0 0,$size $size,0 fill white circle $((size/2)),$((size/2)) $((size/2)),0" \
    \( +clone -flip \) -compose Multiply -composite \
    \( +clone -flop \) -compose Multiply -composite \) \
    -alpha off -compose CopyOpacity -composite \
    "$OUT/android/mipmap-$dir/ic_launcher_round.png"
done

# Android foreground (adaptive icons)
magick "$TMP/base.png" -resize 72x72   -gravity center -background white -extent 108x108 "$OUT/android/mipmap-mdpi/ic_launcher_foreground.png"
magick "$TMP/base.png" -resize 108x108 -gravity center -background white -extent 162x162 "$OUT/android/mipmap-hdpi/ic_launcher_foreground.png"
magick "$TMP/base.png" -resize 144x144 -gravity center -background white -extent 216x216 "$OUT/android/mipmap-xhdpi/ic_launcher_foreground.png"
magick "$TMP/base.png" -resize 216x216 -gravity center -background white -extent 324x324 "$OUT/android/mipmap-xxhdpi/ic_launcher_foreground.png"
magick "$TMP/base.png" -resize 288x288 -gravity center -background white -extent 432x432 "$OUT/android/mipmap-xxxhdpi/ic_launcher_foreground.png"

cat > "$OUT/android/mipmap-anydpi-v26/ic_launcher.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
  <background android:drawable="@color/ic_launcher_background"/>
  <foreground android:drawable="@mipmap/ic_launcher_foreground"/>
</adaptive-icon>
EOF

cat > "$OUT/android/values/ic_launcher_background.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
  <color name="ic_launcher_background">#FFFFFF</color>
</resources>
EOF

echo "Done! Icons generated in $OUT"

// Draws the app icon (the shield of the web UI on a dark rounded square)
// as a 1024×1024 PNG: swift packaging/macos/icon.swift OUT.png
// scripts/make-app.sh turns it into AppIcon.icns.

import AppKit

let size: CGFloat = 1024
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon.png"
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                           bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

// macOS icon grid: the body is 824 of 1024, corner radius about 185.
let body = NSRect(x: 100, y: 100, width: 824, height: 824)
let bg = NSBezierPath(roundedRect: body, xRadius: 185, yRadius: 185)
NSGradient(starting: NSColor(srgbRed: 0.10, green: 0.13, blue: 0.24, alpha: 1),
           ending: NSColor(srgbRed: 0.03, green: 0.04, blue: 0.08, alpha: 1))!.draw(in: bg, angle: -90)

// The shield from the web UI: M10 1 2 4v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V4z (20×22).
let scale: CGFloat = 24, ox: CGFloat = 512 - 10 * scale, oy: CGFloat = 512 + 11 * scale
func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: ox + x * scale, y: oy - y * scale) }
let shield = NSBezierPath()
shield.move(to: p(10, 1))
shield.line(to: p(2, 4))
shield.line(to: p(2, 10))
shield.curve(to: p(10, 21), controlPoint1: p(2, 15), controlPoint2: p(5.4, 19.4))
shield.curve(to: p(18, 10), controlPoint1: p(14.6, 19.4), controlPoint2: p(18, 15))
shield.line(to: p(18, 4))
shield.close()
NSGradient(starting: NSColor(srgbRed: 0.42, green: 0.62, blue: 1, alpha: 1),
           ending: NSColor(srgbRed: 0.18, green: 0.40, blue: 0.95, alpha: 1))!.draw(in: shield, angle: -90)

// A check mark inside: the machine is being looked after.
let check = NSBezierPath()
check.move(to: p(6.3, 11))
check.line(to: p(9, 13.7))
check.line(to: p(13.9, 8.2))
check.lineWidth = 1.7 * scale
check.lineCapStyle = .round
check.lineJoinStyle = .round
NSColor.white.setStroke()
check.stroke()

NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))

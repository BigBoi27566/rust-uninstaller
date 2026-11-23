import os
from PIL import Image, ImageDraw

def create_icon():
    S = 1024  # High-res canvas for supersampling
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Background Squircle
    margin = 56
    radius = 180
    bg_box = [margin, margin, S - margin, S - margin]
    
    # Charcoal body
    draw.rounded_rectangle(bg_box, radius=radius, fill=(20, 20, 20, 255), outline=(45, 45, 45, 255), width=8)

    # 2. Geometric "R" in Pure White
    white = (255, 255, 255, 255)
    
    # Left vertical stem
    stem_x1, stem_x2 = 250, 370
    stem_y1, stem_y2 = 230, 794
    draw.rounded_rectangle([stem_x1, stem_y1, stem_x2, stem_y2], radius=16, fill=white)

    # Top loop outer shape
    # Connects to stem at x=360, extends to x=710, y from 230 to 520
    loop_outer = [360, 230, 710, 520]
    draw.rounded_rectangle(loop_outer, radius=145, fill=white)

    # Top loop inner cutout (dark background color)
    cutout = [370, 330, 590, 420]
    draw.rounded_rectangle(cutout, radius=45, fill=(20, 20, 20, 255))

    # Re-fill connection area between stem and loop so it's a seamless single glyph
    draw.rectangle([350, 230, 380, 520], fill=white)
    draw.rectangle([370, 330, 430, 420], fill=(20, 20, 20, 255))

    # Diagonal sweep leg (Uninstaller Eject Blade)
    # Starts at base of the loop and shoots down-right at 45 degrees
    leg_poly = [
        (450, 490),   # Top-left join under loop
        (570, 490),   # Top-right join under loop
        (780, 700),   # Outer slope
        (780, 794),   # Bottom-right sharp uninstaller tip
        (660, 794),   # Bottom inner
        (450, 584),   # Inner slope
    ]
    draw.polygon(leg_poly, fill=white)

    # Add a dynamic 45-degree negative-space slice (sweep gap) at the leg joint
    # giving it the high-tech, precision uninstaller character
    draw.line([(430, 530), (510, 610)], fill=(20, 20, 20, 255), width=24)

    # 3. Downscale and export
    assets_dir = os.path.dirname(os.path.abspath(__file__))
    png_path = os.path.join(assets_dir, "icon.png")
    ico_path = os.path.join(assets_dir, "icon.ico")

    # Save 256x256 PNG
    img_256 = img.resize((256, 256), Image.Resampling.LANCZOS)
    img_256.save(png_path, "PNG")
    print(f"Saved {png_path}")

    # Generate ICO sizes
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    ico_images = [img.resize(s, Image.Resampling.LANCZOS) for s in sizes]
    ico_images[0].save(ico_path, format="ICO", sizes=sizes, append_images=ico_images[1:])
    print(f"Saved {ico_path}")

if __name__ == "__main__":
    create_icon()

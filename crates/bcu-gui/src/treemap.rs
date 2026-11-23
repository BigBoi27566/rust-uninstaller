use eframe::egui::{self, Color32, Pos2, Rect, Response, Sense, Stroke, Ui};

/// A single application data item to be displayed in the TreeMap.
#[derive(Debug, Clone)]
pub struct TreeMapItem {
    pub original_index: usize,
    pub label: String,
    pub sublabel: String,
    pub size_bytes: u64,
    pub color: Color32,
}

/// A computed layout tile ready for drawing.
#[derive(Debug, Clone)]
pub struct TreeMapTile {
    pub item: TreeMapItem,
    pub rect: Rect,
}

const FALLBACK_SIZE_BYTES: u64 = 5 * 1024 * 1024; // 5 MB nominal fallback

/// Layout engine for Squarified Treemaps (Bruls, Huizing, van Wijk).
pub struct SquarifiedTreeMap;

impl SquarifiedTreeMap {
    /// Computes squarified tile rectangles for a list of items within the given bounding box.
    pub fn compute_layout(
        items: &[TreeMapItem],
        bounds: Rect,
    ) -> Vec<TreeMapTile> {
        if items.is_empty() || bounds.width() <= 1.0 || bounds.height() <= 1.0 {
            return Vec::new();
        }

        // 1. Prepare items and assign fallback weights for zero/missing sizes
        let mut prepared: Vec<(TreeMapItem, f64)> = items
            .iter()
            .map(|item| {
                let size = if item.size_bytes > 0 {
                    item.size_bytes
                } else {
                    FALLBACK_SIZE_BYTES
                };
                (item.clone(), size as f64)
            })
            .collect();

        // Sort descending by weight
        prepared.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let total_weight: f64 = prepared.iter().map(|(_, w)| *w).sum();
        if total_weight <= 0.0 {
            return Vec::new();
        }

        let total_area = (bounds.width() as f64) * (bounds.height() as f64);
        let normalized_items: Vec<(TreeMapItem, f64)> = prepared
            .into_iter()
            .map(|(item, w)| (item, (w / total_weight) * total_area))
            .collect();

        let mut tiles = Vec::with_capacity(normalized_items.len());
        let mut remaining_bounds = bounds;
        let mut current_row: Vec<(TreeMapItem, f64)> = Vec::new();

        for (item, area) in normalized_items {
            let shorter_side = remaining_bounds.width().min(remaining_bounds.height()) as f64;
            if shorter_side <= 0.0 {
                break;
            }

            if current_row.is_empty() {
                current_row.push((item, area));
            } else {
                let mut candidate = current_row.clone();
                candidate.push((item.clone(), area));

                if Self::worst_aspect_ratio(&candidate, shorter_side)
                    <= Self::worst_aspect_ratio(&current_row, shorter_side)
                {
                    current_row = candidate;
                } else {
                    // Layout current row and advance remaining_bounds
                    Self::layout_row(&current_row, &mut remaining_bounds, &mut tiles);
                    current_row = vec![(item, area)];
                }
            }
        }

        if !current_row.is_empty() {
            Self::layout_row(&current_row, &mut remaining_bounds, &mut tiles);
        }

        tiles
    }

    fn worst_aspect_ratio(row: &[(TreeMapItem, f64)], side: f64) -> f64 {
        if row.is_empty() || side <= 0.0 {
            return f64::MAX;
        }

        let sum: f64 = row.iter().map(|(_, a)| *a).sum();
        if sum <= 0.0 {
            return f64::MAX;
        }

        let side_sq = side * side;
        let sum_sq = sum * sum;

        let mut max_ratio = 0.0;
        for (_, a) in row {
            if *a <= 0.0 {
                continue;
            }
            let r1 = (side_sq * *a) / sum_sq;
            let r2 = sum_sq / (side_sq * *a);
            let ratio = r1.max(r2);
            if ratio > max_ratio {
                max_ratio = ratio;
            }
        }

        max_ratio
    }

    fn layout_row(
        row: &[(TreeMapItem, f64)],
        bounds: &mut Rect,
        tiles: &mut Vec<TreeMapTile>,
    ) {
        if row.is_empty() || bounds.width() <= 0.0 || bounds.height() <= 0.0 {
            return;
        }

        let sum: f64 = row.iter().map(|(_, a)| *a).sum();
        if sum <= 0.0 {
            return;
        }

        let is_horizontal = bounds.width() >= bounds.height();
        if is_horizontal {
            // Split along width: row has height = bounds.height(), thickness along X
            let thickness = (sum / bounds.height() as f64).min(bounds.width() as f64) as f32;
            let mut current_y = bounds.min.y;

            for (item, area) in row {
                let item_height = if sum > 0.0 {
                    ((*area / sum) * bounds.height() as f64) as f32
                } else {
                    0.0
                };

                let tile_rect = Rect::from_min_max(
                    Pos2::new(bounds.min.x, current_y),
                    Pos2::new(bounds.min.x + thickness, (current_y + item_height).min(bounds.max.y)),
                );

                tiles.push(TreeMapTile {
                    item: item.clone(),
                    rect: tile_rect,
                });

                current_y += item_height;
            }

            bounds.min.x += thickness;
        } else {
            // Split along height: row has width = bounds.width(), thickness along Y
            let thickness = (sum / bounds.width() as f64).min(bounds.height() as f64) as f32;
            let mut current_x = bounds.min.x;

            for (item, area) in row {
                let item_width = if sum > 0.0 {
                    ((*area / sum) * bounds.width() as f64) as f32
                } else {
                    0.0
                };

                let tile_rect = Rect::from_min_max(
                    Pos2::new(current_x, bounds.min.y),
                    Pos2::new((current_x + item_width).min(bounds.max.x), bounds.min.y + thickness),
                );

                tiles.push(TreeMapTile {
                    item: item.clone(),
                    rect: tile_rect,
                });

                current_x += item_width;
            }

            bounds.min.y += thickness;
        }
    }
}

/// Helper function to format bytes into readable KB/MB/GB string.
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

/// Renders the interactive Squarified TreeMap inside an `egui::Ui`.
/// Returns `Some(original_index)` if an application tile was clicked.
pub fn render_treemap(
    ui: &mut Ui,
    tiles: &[TreeMapTile],
    selected_index: Option<usize>,
) -> Option<usize> {
    let mut clicked_index = None;

    for tile in tiles {
        let is_selected = selected_index == Some(tile.item.original_index);

        // Allocate click and hover interaction for the tile rectangle
        let response: Response = ui.allocate_rect(tile.rect, Sense::click());

        let fill_color = if response.hovered() {
            // Brighten slightly on hover
            Color32::from_rgba_premultiplied(
                tile.item.color.r().saturating_add(30),
                tile.item.color.g().saturating_add(30),
                tile.item.color.b().saturating_add(30),
                tile.item.color.a(),
            )
        } else {
            tile.item.color
        };

        let stroke = if is_selected {
            Stroke::new(2.5_f32, Color32::WHITE)
        } else if response.hovered() {
            Stroke::new(1.5_f32, Color32::from_gray(220))
        } else {
            Stroke::new(1.0_f32, Color32::from_black_alpha(80))
        };

        // Draw tile body
        ui.painter().rect(tile.rect, 2.0, fill_color, stroke);

        // Draw text label if tile is sufficiently large
        if tile.rect.width() > 45.0 && tile.rect.height() > 18.0 {
            let text_rect = tile.rect.shrink(3.0);
            let display_text = if tile.rect.height() > 32.0 {
                format!("{}\n{}", tile.item.label, format_bytes(tile.item.size_bytes))
            } else {
                tile.item.label.clone()
            };

            ui.painter().text(
                text_rect.min,
                egui::Align2::LEFT_TOP,
                display_text,
                egui::FontId::proportional(11.0),
                Color32::WHITE,
            );
        }

        // Show detailed tooltip on hover
        if response.hovered() {
            response.show_tooltip_text(format!(
                "{}\nPublisher: {}\nEstimated Size: {}",
                tile.item.label,
                if tile.item.sublabel.is_empty() { "Unknown" } else { &tile.item.sublabel },
                format_bytes(tile.item.size_bytes),
            ));
        }

        if response.clicked() {
            clicked_index = Some(tile.item.original_index);
        }
    }

    clicked_index
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::egui::Vec2;

    #[test]
    fn test_empty_treemap_returns_empty() {
        let bounds = Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 600.0));
        let tiles = SquarifiedTreeMap::compute_layout(&[], bounds);
        assert!(tiles.is_empty());
    }

    #[test]
    fn test_single_item_fills_bounds() {
        let bounds = Rect::from_min_size(Pos2::ZERO, Vec2::new(400.0, 300.0));
        let items = vec![TreeMapItem {
            original_index: 0,
            label: "Solo App".into(),
            sublabel: "Vendor".into(),
            size_bytes: 100 * 1024 * 1024,
            color: Color32::BLUE,
        }];

        let tiles = SquarifiedTreeMap::compute_layout(&items, bounds);
        assert_eq!(tiles.len(), 1);
        let rect = tiles[0].rect;
        assert_eq!(rect.min, Pos2::ZERO);
        assert!((rect.width() - 400.0).abs() < 1.0);
        assert!((rect.height() - 300.0).abs() < 1.0);
    }

    #[test]
    fn test_area_conservation_and_bounds() {
        let bounds = Rect::from_min_size(Pos2::new(10.0, 20.0), Vec2::new(500.0, 400.0));
        let items = vec![
            TreeMapItem {
                original_index: 0,
                label: "App A".into(),
                sublabel: "".into(),
                size_bytes: 500 * 1024 * 1024,
                color: Color32::RED,
            },
            TreeMapItem {
                original_index: 1,
                label: "App B".into(),
                sublabel: "".into(),
                size_bytes: 300 * 1024 * 1024,
                color: Color32::GREEN,
            },
            TreeMapItem {
                original_index: 2,
                label: "App C".into(),
                sublabel: "".into(),
                size_bytes: 200 * 1024 * 1024,
                color: Color32::BLUE,
            },
        ];

        let tiles = SquarifiedTreeMap::compute_layout(&items, bounds);
        assert_eq!(tiles.len(), 3);

        let container_area = 500.0 * 400.0;
        let sum_tile_area: f32 = tiles.iter().map(|t| t.rect.width() * t.rect.height()).sum();
        assert!(
            (sum_tile_area - container_area).abs() < 5.0,
            "Sum of tile areas ({}) must equal container area ({})",
            sum_tile_area,
            container_area
        );

        for tile in &tiles {
            assert!(tile.rect.min.x >= bounds.min.x - 0.1);
            assert!(tile.rect.min.y >= bounds.min.y - 0.1);
            assert!(tile.rect.max.x <= bounds.max.x + 0.1);
            assert!(tile.rect.max.y <= bounds.max.y + 0.1);
        }
    }

    #[test]
    fn test_zero_sized_item_uses_fallback() {
        let bounds = Rect::from_min_size(Pos2::ZERO, Vec2::new(200.0, 200.0));
        let items = vec![TreeMapItem {
            original_index: 42,
            label: "Zero Size App".into(),
            sublabel: "".into(),
            size_bytes: 0,
            color: Color32::GRAY,
        }];

        let tiles = SquarifiedTreeMap::compute_layout(&items, bounds);
        assert_eq!(tiles.len(), 1);
        assert!(tiles[0].rect.width() > 10.0);
        assert!(tiles[0].rect.height() > 10.0);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2 KB");
        assert_eq!(format_bytes(10 * 1024 * 1024), "10.0 MB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GB");
    }
}
